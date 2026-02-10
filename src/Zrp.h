//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef ZRP_H_
#define ZRP_H_

#include <map>
#include <vector>
#include <queue>
#include <set>

// Must be defined before including ZrpControlPackets_m.h
#define IARP_METRIC_COUNT 1

#include "inet/common/ModuleRefByPar.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "ZrpControlPackets_m.h"
#include "ZrpRouteData.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"



//As the RFC assumes a 32 bit address only IPv4 is to be supported

using namespace inet;

namespace zrp {

// Sequence number utilities (RFC 1982 serial number arithmetic for 16-bit)
// Handles wrap-around correctly: 0 is considered "newer" than 65535

// Returns true if seq1 is strictly newer than seq2 (handles wrap-around)
inline bool seqNumIsNewer(uint16_t seq1, uint16_t seq2) {
    // Using signed comparison of the difference handles wrap-around
    // e.g., if seq1=0, seq2=65535, diff=1 (positive) -> seq1 is newer
    return (int16_t)(seq1 - seq2) > 0;
}

// Returns true if seq1 is newer than or equal to seq2
inline bool seqNumIsNewerOrEqual(uint16_t seq1, uint16_t seq2) {
    return seq1 == seq2 || seqNumIsNewer(seq1, seq2);
}

// Self-message kind constants
// These identify the purpose of dynamically created self-messages
// (for timers that carry data, as opposed to the fixed-pointer timers
// like NDP_helloTimer). This pattern supports a variable number of
// concurrent timers, each carrying context about which query/packet
// they correspond to.
enum ZrpSelfMsgKind {
    ZRP_SELF_NDP_HELLO    = 0,    // Fixed timer
    ZRP_SELF_IARP_UPDATE  = 1,    // Fixed timer
    ZRP_SELF_DEBUG        = 2,    // Fixed timer
    ZRP_SELF_BRP_JITTER   = 10,   // Variable: BRP jitter delivery to IERP (carries BRP packet data)
};

// Unique identifier for an IERP route query in the network.
// Combination of (source address, query ID) is globally unique.
struct IerpQueryId {
    L3Address source;
    uint16_t queryId;

    bool operator==(const IerpQueryId& other) const {
        return source == other.source && queryId == other.queryId;
    }
    bool operator<(const IerpQueryId& other) const {
        if (source == other.source) return queryId < other.queryId;
        return source < other.source;
    }
};

// Link destination info for the link state table
struct LinkDestInfo {
    L3Address destAddr;
    uint16_t metrics[IARP_METRIC_COUNT];  // metric values (e.g., hop count)
};

// Link state table entry - stores link state info from a source node
struct LinkStateEntry {
    L3Address sourceAddr;           // Node that originated this link state
    unsigned int zoneRadius;        // Zone radius of the source node
    unsigned int seqNum;            // Link state sequence number
    simtime_t insertTime;           // When this entry was inserted/updated
    std::vector<LinkDestInfo> linkDestinations;  // List of neighbors and their metrics
};

// IERP detected query record - used to detect and discard duplicate queries.
// Per RFC IERP Section 5.E.3: "if ((EXISTS) IERP_Routing_Table[dest].route)"
// also implicitly means we've seen this query before if it's in the table.
struct IerpQueryRecord {
    IerpQueryId queryId;        // Source + query ID
    L3Address destination;      // The query destination
    simtime_t receiveTime;      // When we first saw this query
    bool replied;               // Whether we sent/forwarded a reply
};

// Pending jitter timer entry - tracks dynamically created self-messages
// that carry data (e.g., BRP jitter delays). Stored so they can be
// cancelled during clearState().
struct PendingTimerEntry {
    cMessage *msg;
};

// Output operator for LinkStateEntry - required for WATCH_MAP to display entries
inline std::ostream& operator<<(std::ostream& os, const LinkStateEntry& entry) {
    os << "src=" << entry.sourceAddr 
       << " seq=" << entry.seqNum 
       << " zone=" << entry.zoneRadius
       << " neighbors=" << entry.linkDestinations.size()
       << " age=" << (simTime() - entry.insertTime).dbl() << "s";
    return os;
}

class INET_API Zrp : public RoutingProtocolBase,  public NetfilterBase::HookBase, public UdpSocket::ICallback, public cListener 
{
  protected:
    //context

    //environment
    cModule *host = nullptr;
    ModuleRefByPar<IRoutingTable> routingTable;
    ModuleRefByPar<IInterfaceTable> interfaceTable;
    ModuleRefByPar<INetfilter> networkProtocol;
    UdpSocket socket;

    //parameters
    simtime_t linkStateLifetime = 3;
    simtime_t IARP_updateInterval = 3;
    unsigned int zoneRadius = 2;
    unsigned int zrpUDPPort = 0;
    simtime_t NDP_helloInterval = 3;
    simtime_t debugInterval = 0;  // 0 = disabled

    // state - NDP/IARP
    unsigned int NDP_seqNum = 0;  // sequence number for NDP hello messages
    unsigned int IARP_seqNum = 0; // sequence number for IARP link state updates
    std::map<L3Address, simtime_t> neighborTable;  // neighbor address -> last heard time
    std::map<L3Address, LinkStateEntry> linkStateTable;  // source address -> link state entry

    // state - IERP
    uint16_t IERP_queryId = 0;  // locally unique query ID counter
    // Query detection table: tracks queries we've seen to detect duplicates
    // Key: (source, queryID), Value: record of the query
    std::map<IerpQueryId, IerpQueryRecord> ierpQueryTable;

    // Buffered datagrams waiting for route discovery to complete
    std::multimap<L3Address, Packet *> delayedPackets;

    // Pending jitter timers - dynamically created self-messages carrying context data.
    // BRP will schedule these with random delay so the node can collect coverage
    // info from other bordercasts before forwarding. We track them here so
    // clearState() can cancel them all.
    std::vector<cMessage*> pendingTimers;

    // self messages (fixed timers - identified by pointer comparison)
    cMessage *NDP_helloTimer = nullptr;
    cMessage *IARP_updateTimer = nullptr;
    cMessage *debugTimer = nullptr;

  protected:
    void handleMessageWhenUp(cMessage *msg) override;
    void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void refreshDisplay() const override;  // Update visual display

    //Lifecycle
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    //Netfilter hooks
    virtual Result datagramPreRoutingHook(Packet *datagram) override;
    virtual Result datagramForwardHook(Packet *datagram) override;
    virtual Result datagramPostRoutingHook(Packet *datagram) override;
    virtual Result datagramLocalInHook(Packet *datagram) override;
    virtual Result datagramLocalOutHook(Packet *datagram) override;

    //UDP callback interface
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

    //cListener
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;

    //Helper functions
    L3Address getSelfIPAddress() const;
    int getNumIarpRoutes() const;  // Count routes we've installed
    void clearState();
    void printDebugTables();  // Pretty-print all tables to EV_INFO
    void processPacket(Packet *packet);
    void sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl);

    // NDP Functions
    const Ptr<inet::zrp::NDP_Hello> createNDPHello();
    void sendNDPHello();
    void handleNDPHello(const Ptr<inet::zrp::NDP_Hello>& hello, const L3Address& sourceAddr);
    void NDP_refreshNeighborTable();

    //IARP Functions
    const Ptr<inet::zrp::IARP_LinkStateUpdate> createIARPUpdate();
    void sendIARPUpdate();
    void handleIARPUpdate(const Ptr<inet::zrp::IARP_LinkStateUpdate>& update, const L3Address& sourceAddr);
    void IARP_refreshLinkStateTable();
    void IARP_updateRoutingTable();
    void IARP_purgeRoutingTable();
    void IARP_computeRoutes();
    IRoute *IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops);

    // IERP Functions
    // Route discovery initiation (called when no route exists for outgoing data)
    void IERP_initiateRouteDiscovery(const L3Address& dest);

    // Packet creation
    const Ptr<inet::zrp::IERP_RouteData> IERP_createRouteRequest(const L3Address& dest);
    const Ptr<inet::zrp::IERP_RouteData> IERP_createRouteReply(const Ptr<inet::zrp::IERP_RouteData>& request);

    // Packet handling - called when IERP packets arrive (via BRP delivery or direct IP)
    void IERP_handleRouteRequest(const Ptr<inet::zrp::IERP_RouteData>& request, const L3Address& sourceAddr);
    void IERP_handleRouteReply(const Ptr<inet::zrp::IERP_RouteData>& reply, const L3Address& sourceAddr);

    // Route maintenance - called when IARP detects a topology change
    void IERP_routeMaintenance();

    // Route table helpers
    IRoute *IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                             const std::vector<L3Address>& fullRoute);
    void IERP_purgeRoutingTable();
    bool IERP_hasRouteToDestination(const L3Address& dest) const;
    IRoute *IERP_findRoute(const L3Address& dest) const;
    bool IERP_hasOngoingDiscovery(const L3Address& dest) const;
    void IERP_delayDatagram(Packet *datagram);
    void IERP_completeRouteDiscovery(const L3Address& dest);

    // Query tracking
    bool IERP_isQuerySeen(const IerpQueryId& qid) const;
    void IERP_recordQuery(const IerpQueryId& qid, const L3Address& dest);
    void IERP_cleanQueryTable();  // Remove old query records

    // Packet field helpers (extract/load per RFC pseudocode)
    // extract() populates local variables from an IERP packet
    // load() writes local variables back into an IERP packet (handled by setters)

    // BRP interface stubs (to be implemented with BRP later)
    // bordercast() replaces traditional broadcast() per RFC IERP Section 4
    void BRP_bordercast(const Ptr<inet::zrp::IERP_RouteData>& packet, int brpCacheId);

    // Pending timer management
    void schedulePendingTimer(cMessage *msg, simtime_t delay);
    void cancelPendingTimer(cMessage *msg);
    void cancelAllPendingTimers();


  public:
    Zrp();
    virtual ~Zrp();
};

} // namespace zrp



#endif //ZRP_H_
