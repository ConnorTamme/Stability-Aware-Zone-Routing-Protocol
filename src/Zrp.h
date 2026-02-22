// Connor Tamme, tammeconnor@gmail.com
//
// Main header of the ZRP implementation.
//

#ifndef ZRP_H_
#define ZRP_H_

#include <map>
#include <vector>
#include <queue>
#include <set>

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

// As the RFC assumes a 32 bit address only IPv4 is supported

namespace inet {
namespace zrp {

// Returns true if seq1 is newer than seq2 (handles wrap around)
inline bool seqNumIsNewer(uint16_t seq1, uint16_t seq2)
{
    // Using signed comparison of the difference handles wrap around
    return (int16_t)(seq1 - seq2) > 0;
}

// Returns true if seq1 is newer than or equal to seq2
inline bool seqNumIsNewerOrEqual(uint16_t seq1, uint16_t seq2)
{
    return seq1 == seq2 || seqNumIsNewer(seq1, seq2);
}

// Self-message types
enum ZrpSelfMsgType {
    ZRP_SELF_NDP_HELLO = 0,   // Fixed timer
    ZRP_SELF_IARP_UPDATE = 1, // Fixed timer
    ZRP_SELF_DEBUG = 2,       // Fixed timer
    ZRP_SELF_BRP_JITTER = 10, // Variable: BRP jitter delivery to IERP (carries BRP packet data)
    ZRP_SELF_IERP_RETRY = 11, // Variable: IERP route request retry timer
};

// IERP query identifier. The (source, queryId) pair is globally unique
struct IerpQueryId {
    L3Address source;
    uint16_t queryId;

    bool operator==(const IerpQueryId& other) const { return source == other.source && queryId == other.queryId; }
    bool operator<(const IerpQueryId& other) const
    {
        if (source == other.source)
            return queryId < other.queryId;
        return source < other.source;
    }
};

// Link destination info for the link state table
struct LinkDestInfo {
    L3Address destAddr;
    uint16_t metrics[IARP_METRIC_COUNT]; // metric values (hop count is the main one, but others are allowed)
};

// Link state entry from a source node
struct LinkStateEntry {
    L3Address sourceAddr;                       // Node that originated this link state
    unsigned int zoneRadius;                    // Zone radius of the source node
    uint16_t seqNum;                            // Link state sequence number
    simtime_t insertTime;                       // When this entry was inserted/updated
    std::vector<LinkDestInfo> linkDestinations; // List of neighbours and their metrics
};

// Recorded query for duplicate detection
struct IerpQueryRecord {
    IerpQueryId queryId;   // Source + query ID
    L3Address destination; // The query destination
    simtime_t receiveTime; // When we first saw this query
    bool replied;          // Whether we sent/forwarded a reply
};

// Pending timer entry, tracked for clearState() cleanup
struct PendingTimerEntry {
    cMessage* msg;
};

// Required for WATCH_MAP display
inline std::ostream& operator<<(std::ostream& os, const LinkStateEntry& entry)
{
    os << "src=" << entry.sourceAddr << " seq=" << entry.seqNum << " zone=" << entry.zoneRadius
       << " neighbours=" << entry.linkDestinations.size() << " age=" << (simTime() - entry.insertTime).dbl() << "s";
    return os;
}

class INET_API Zrp : public RoutingProtocolBase,
                     public NetfilterBase::HookBase,
                     public UdpSocket::ICallback,
                     public cListener {
  protected:
    // environment
    cModule* host = nullptr;
    ModuleRefByPar<IRoutingTable> routingTable;
    ModuleRefByPar<IInterfaceTable> interfaceTable;
    ModuleRefByPar<INetfilter> networkProtocol;
    UdpSocket socket;

    // parameters
    simtime_t linkStateLifetime = 3;
    simtime_t IARP_updateInterval = 3;
    unsigned int zoneRadius = 2;
    unsigned int zrpUDPPort = 0;
    simtime_t NDP_helloInterval = 3;
    simtime_t debugInterval = 0;        // 0 = disabled
    simtime_t brpJitterMax = 0.1;       // Max random jitter for BRP relay (RFC: RELAY_JITTER)
    simtime_t brpCoverageLifetime = 30; // How long to keep coverage entries (RFC: MAX_QUERY_LIFETIME)
    simtime_t ierpRetryInterval = 3;    // How long to wait before retrying a route request
    unsigned int ierpMaxRetries = 3;    // Max number of IERP route request retries

    // NDP/IARP
    uint16_t NDP_seqNum = 0;                            // sequence number for NDP hello messages (wraps at 65535)
    uint16_t IARP_seqNum = 0;                           // sequence number for IARP link state updates (wraps at 65535)
    std::map<L3Address, simtime_t> neighbourTable;       // neighbour address -> last heard time
    std::map<L3Address, LinkStateEntry> linkStateTable; // source address -> link state entry

    // IERP
    uint16_t IERP_queryId = 0; // locally unique query ID counter
    // Query detection table: (source, queryID) -> record
    std::map<IerpQueryId, IerpQueryRecord> ierpQueryTable;

    // Buffered datagrams waiting for route discovery to complete
    std::multimap<L3Address, Packet*> delayedPackets;

    // IERP route request retry state
    std::map<L3Address, cMessage*> ierpRetryTimers; // dest -> retry timer
    std::map<L3Address, int> ierpRetryCounters;     // dest -> retry count

    // BRP
    uint16_t BRP_bordercastId = 0; // locally unique bordercast ID counter
    // BRP query coverage table
    struct BrpQueryCoverage {
        IerpQueryId queryId;              // The IERP query this coverage tracks
        int brpCacheId;                   // Locally unique cache ID for this entry
        std::set<L3Address> coveredNodes; // Set of nodes covered by this query
        simtime_t createTime;             // When this coverage entry was created
        bool delivered;                   // True once we've scheduled/completed IERP delivery for this query
    };
    // Key is brpCacheId
    std::map<int, BrpQueryCoverage> brpCoverageTable;

    // Pending BRP jitter timers, tracked for clearState() cleanup
    std::vector<cMessage*> pendingTimers;

    // Fixed timers
    cMessage* NDP_helloTimer = nullptr;
    cMessage* IARP_updateTimer = nullptr;
    cMessage* debugTimer = nullptr;

  protected:
    void handleMessageWhenUp(cMessage* msg) override;
    void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void refreshDisplay() const override;

    // Lifecycle
    virtual void handleStartOperation(LifecycleOperation* operation) override;
    virtual void handleStopOperation(LifecycleOperation* operation) override;
    virtual void handleCrashOperation(LifecycleOperation* operation) override;

    // Netfilter hooks
    virtual Result datagramPreRoutingHook(Packet* datagram) override;
    virtual Result datagramForwardHook(Packet* datagram) override;
    virtual Result datagramPostRoutingHook(Packet* datagram) override;
    virtual Result datagramLocalInHook(Packet* datagram) override;
    virtual Result datagramLocalOutHook(Packet* datagram) override;

    // UDP socket stuff
    virtual void socketDataArrived(UdpSocket* socket, Packet* packet) override;
    virtual void socketErrorArrived(UdpSocket* socket, Indication* indication) override;
    virtual void socketClosed(UdpSocket* socket) override;

    // cListener
    virtual void receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details) override;

    // Helper functions
    L3Address getSelfIPAddress() const;
    int getNumIarpRoutes() const;
    void clearState();
    void printDebugTables();
    void processPacket(Packet* packet);
    void sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl);

    // NDP Functions
    const Ptr<NDP_Hello> createNDPHello();
    void sendNDPHello();
    void handleNDPHello(const Ptr<NDP_Hello>& hello, const L3Address& sourceAddr);
    void NDP_refreshNeighbourTable();

    // IARP Functions
    const Ptr<IARP_LinkStateUpdate> createIARPUpdate();
    void sendIARPUpdate();
    void handleIARPUpdate(const Ptr<IARP_LinkStateUpdate>& update, const L3Address& sourceAddr);
    void IARP_refreshLinkStateTable();
    void IARP_updateRoutingTable();
    void IARP_purgeRoutingTable();
    void IARP_computeRoutes();
    std::vector<L3Address> IARP_getRoutePath(const L3Address& dest) const;
    IRoute* IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops);

    // IERP Functions
    // Route discovery initiation
    void IERP_initiateRouteDiscovery(const L3Address& dest);

    // Packet creation
    const Ptr<IERP_RouteData> IERP_createRouteRequest(const L3Address& dest);
    const Ptr<IERP_RouteData> IERP_createRouteReply(const Ptr<IERP_RouteData>& request);

    // Packet handling. Called when IERP packets arrive (via BRP delivery or direct IP)
    void IERP_handleRouteRequest(const Ptr<IERP_RouteData>& request, const L3Address& sourceAddr);
    void IERP_handleRouteReply(const Ptr<IERP_RouteData>& reply, const L3Address& sourceAddr);

    // Route maintenance. Called when IARP detects a topology change
    void IERP_routeMaintenance();

    // Route table helpers
    IRoute* IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                             const std::vector<L3Address>& fullRoute);
    void IERP_purgeRoutingTable();
    bool IERP_hasRouteToDestination(const L3Address& dest) const;
    IRoute* IERP_findRoute(const L3Address& dest) const;
    bool IERP_hasOngoingDiscovery(const L3Address& dest) const;
    void IERP_delayDatagram(Packet* datagram);
    void IERP_completeRouteDiscovery(const L3Address& dest);

    // Query tracking
    bool IERP_isQuerySeen(const IerpQueryId& qid) const;
    void IERP_recordQuery(const IerpQueryId& qid, const L3Address& dest);
    void IERP_cleanQueryTable(); // Remove old query records

    // BRP Functions
    void BRP_bordercast(const Ptr<IERP_RouteData>& packet);
    void BRP_deliver(const Ptr<BRP_Data>& brpPacket, const L3Address& sourceAddr);

    // BRP helpers
    std::set<L3Address> BRP_getMyZone() const;
    std::set<L3Address> BRP_getMyPeripherals() const;
    std::set<L3Address> BRP_getOutNeighbours(const std::set<L3Address>& uncoveredPeripherals) const;
    bool BRP_isOutNeighbour(const L3Address& prevBordercaster, const L3Address& node,
                           const std::set<L3Address>& coveredNodes, std::set<L3Address>& outPrevZone) const;
    void BRP_recordCoverage(int brpCacheId, const std::set<L3Address>& nodes);
    int BRP_findOrCreateCoverage(const IerpQueryId& qid);
    void BRP_cleanCoverageTable();

    // Pending timer management
    void schedulePendingTimer(cMessage* msg, simtime_t delay);
    void cancelPendingTimer(cMessage* msg);
    void cancelAllPendingTimers();

  public:
    Zrp();
    virtual ~Zrp();
};

} // namespace zrp
} // namespace inet

#endif // ZRP_H_
