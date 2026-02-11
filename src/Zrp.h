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

namespace inet {
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
    ZRP_SELF_IERP_RETRY   = 11,   // Variable: IERP route request retry timer
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
    uint16_t seqNum;                // Link state sequence number (16-bit, wraps per RFC 1982)
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
    simtime_t brpJitterMax = 0.1;        // Max random jitter for BRP relay (RFC: RELAY_JITTER)
    simtime_t brpCoverageLifetime = 30;  // How long to keep coverage entries (RFC: MAX_QUERY_LIFETIME)
    simtime_t ierpRetryInterval = 3;     // How long to wait before retrying a route request
    unsigned int ierpMaxRetries = 3;     // Max number of IERP route request retries

    // state - NDP/IARP
    uint16_t NDP_seqNum = 0;  // sequence number for NDP hello messages (wraps at 65535)
    uint16_t IARP_seqNum = 0; // sequence number for IARP link state updates (wraps at 65535)
    std::map<L3Address, simtime_t> neighborTable;  // neighbor address -> last heard time
    std::map<L3Address, LinkStateEntry> linkStateTable;  // source address -> link state entry

    // state - IERP
    uint16_t IERP_queryId = 0;  // locally unique query ID counter
    // Query detection table: tracks queries we've seen to detect duplicates
    // Key: (source, queryID), Value: record of the query
    std::map<IerpQueryId, IerpQueryRecord> ierpQueryTable;

    // Buffered datagrams waiting for route discovery to complete
    std::multimap<L3Address, Packet *> delayedPackets;

    // IERP route request retry state
    std::map<L3Address, cMessage*> ierpRetryTimers;  // dest -> retry timer
    std::map<L3Address, int> ierpRetryCounters;      // dest -> retry count

    // state - BRP
    uint16_t BRP_bordercastId = 0;  // locally unique bordercast ID counter
    // BRP Query Coverage Table (RFC BRP Section 4.B.3)
    // Tracks which nodes have been covered per query, so bordercast trees
    // can be pruned to only span uncovered peripheral nodes.
    struct BrpQueryCoverage {
        IerpQueryId queryId;         // The IERP query this coverage tracks
        int brpCacheId;              // Locally unique cache ID for this entry
        std::set<L3Address> coveredNodes;  // Set of nodes covered by this query
        simtime_t createTime;        // When this coverage entry was created
        bool delivered;              // True once we've scheduled/completed IERP delivery for this query
    };
    // Key: brpCacheId -> coverage entry
    std::map<int, BrpQueryCoverage> brpCoverageTable;

    // Pending jitter timers - dynamically created self-messages carrying context data.
    // BRP schedules these with random delay so the node can collect coverage
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
    const Ptr<NDP_Hello> createNDPHello();
    void sendNDPHello();
    void handleNDPHello(const Ptr<NDP_Hello>& hello, const L3Address& sourceAddr);
    void NDP_refreshNeighborTable();

    //IARP Functions
    const Ptr<IARP_LinkStateUpdate> createIARPUpdate();
    void sendIARPUpdate();
    void handleIARPUpdate(const Ptr<IARP_LinkStateUpdate>& update, const L3Address& sourceAddr);
    void IARP_refreshLinkStateTable();
    void IARP_updateRoutingTable();
    void IARP_purgeRoutingTable();
    void IARP_computeRoutes();
    IRoute *IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops);

    // IERP Functions
    // Route discovery initiation (called when no route exists for outgoing data)
    void IERP_initiateRouteDiscovery(const L3Address& dest);

    // Packet creation
    const Ptr<IERP_RouteData> IERP_createRouteRequest(const L3Address& dest);
    const Ptr<IERP_RouteData> IERP_createRouteReply(const Ptr<IERP_RouteData>& request);

    // Packet handling - called when IERP packets arrive (via BRP delivery or direct IP)
    void IERP_handleRouteRequest(const Ptr<IERP_RouteData>& request, const L3Address& sourceAddr);
    void IERP_handleRouteReply(const Ptr<IERP_RouteData>& reply, const L3Address& sourceAddr);

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

    // BRP Functions (RFC BRP draft-ietf-manet-zone-brp-02)
    // bordercast() replaces traditional broadcast() per RFC IERP Section 4
    // RFC BRP E.1: Send(encap_packet) - called by IERP
    // Coverage state is resolved internally via BRP_findOrCreateCoverage.
    void BRP_bordercast(const Ptr<IERP_RouteData>& packet);
    // RFC BRP E.2: Deliver(packet) - called when BRP packet arrives from IP
    void BRP_deliver(const Ptr<BRP_Data>& brpPacket, const L3Address& sourceAddr);

    // BRP helper functions
    // Get our own routing zone members (self + all IARP route destinations)
    std::set<L3Address> BRP_getMyZone() const;
    // Get our peripheral nodes (IARP routes at exactly zoneRadius hops)
    std::set<L3Address> BRP_getMyPeripherals() const;
    // Get next-hop neighbors for reaching the given set of (uncovered) peripheral nodes
    // Uses IARP routing table next-hop entries directly
    std::set<L3Address> BRP_getOutNeighbors(const std::set<L3Address>& uncoveredPeripherals) const;
    // Check if 'node' is an outgoing neighbor in prevBordercaster's bordercast tree,
    // and also output the prevBordercaster's routing zone (computed as a byproduct of the Dijkstra)
    bool BRP_isOutNeighbor(const L3Address& prevBordercaster, const L3Address& node,
                           const std::set<L3Address>& coveredNodes,
                           std::set<L3Address>& outPrevZone) const;
    // Mark a set of nodes as covered in a coverage entry
    void BRP_recordCoverage(int brpCacheId, const std::set<L3Address>& nodes);
    // Find or create a coverage entry for a query
    int BRP_findOrCreateCoverage(const IerpQueryId& qid);
    // Clean old coverage entries
    void BRP_cleanCoverageTable();

    // Pending timer management
    void schedulePendingTimer(cMessage *msg, simtime_t delay);
    void cancelPendingTimer(cMessage *msg);
    void cancelAllPendingTimers();


  public:
    Zrp();
    virtual ~Zrp();
};

} // namespace zrp
} // namespace inet

#endif //ZRP_H_
