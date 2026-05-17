//
// Main header of the GZRP (Generalised ZRP) implementation. The structural
// layout (NDP -> IARP -> IERP -> BRP) is inherited from SAZRP; the four
// logical decisions (scoring, decay, gate, threshold) are delegated to
// strategy submodules defined in Strategies/.
//

#ifndef GZRP_H_
#define GZRP_H_

#include <map>
#include <vector>
#include <queue>
#include <set>
#include <string>
#include <utility>

// IARP_METRIC_COUNT / IARP_METRIC_STABILITY come from GzrpControlPackets_m.h
// (defined in its msg cplusplus block) -- keeping them there avoids an
// include cycle through Strategies/IStrategy.h.

#include "inet/common/ModuleRefByPar.h"
#include "inet/common/geometry/common/Coord.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "GzrpControlPackets_m.h"
#include "GzrpRouteData.h"
#include "Strategies/IStrategy.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"

namespace inet {
namespace gzrp {

inline bool seqNumIsNewer(uint16_t seq1, uint16_t seq2)
{
    return (int16_t)(seq1 - seq2) > 0;
}

inline bool seqNumIsNewerOrEqual(uint16_t seq1, uint16_t seq2)
{
    return seq1 == seq2 || seqNumIsNewer(seq1, seq2);
}

enum GzrpSelfMsgType {
    GZRP_SELF_NDP_HELLO = 0,
    GZRP_SELF_IARP_UPDATE = 1,
    GZRP_SELF_DEBUG = 2,
    GZRP_SELF_BRP_JITTER = 10,
    GZRP_SELF_IERP_RETRY = 11,
};

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

struct LinkDestInfo {
    L3Address destAddr;
    uint16_t metrics[IARP_METRIC_COUNT];
};

struct LinkStateEntry {
    L3Address sourceAddr;
    uint16_t seqNum;
    simtime_t insertTime;
    std::vector<LinkDestInfo> linkDestinations;
};

struct IerpQueryRecord {
    IerpQueryId queryId;
    L3Address destination;
    simtime_t receiveTime;
    bool replied;
};

struct PendingTimerEntry {
    cMessage* msg;
};

inline std::ostream& operator<<(std::ostream& os, const LinkStateEntry& entry)
{
    os << "src=" << entry.sourceAddr << " seq=" << entry.seqNum
       << " neighbours=" << entry.linkDestinations.size() << " age=" << (simTime() - entry.insertTime).dbl() << "s";
    return os;
}

inline std::ostream& operator<<(std::ostream& os, const NeighbourState& ns)
{
    os << "lastHeard=" << ns.lastHeard << " quality=" << ns.quality;
    return os;
}

class INET_API Gzrp : public RoutingProtocolBase,
                     public NetfilterBase::HookBase,
                     public UdpSocket::ICallback,
                     public cListener {
  public:
    static simsignal_t controlPacketSentSignal;
    static simsignal_t routeDiscoveryStartedSignal;
    static simsignal_t routeDiscoveryRetriedSignal;

    static simsignal_t pktSentNDPSignal;
    static simsignal_t pktSentIARPSignal;
    static simsignal_t pktSentIERPQuerySignal;
    static simsignal_t pktSentIERPReplySignal;
    static simsignal_t pktSentBRPSignal;

    static simsignal_t routeLengthSignal;
    static simsignal_t routeDiscoveryTimeSignal;

  protected:
    // Environment
    cModule* host = nullptr;
    ModuleRefByPar<IRoutingTable> routingTable;
    ModuleRefByPar<IInterfaceTable> interfaceTable;
    ModuleRefByPar<INetfilter> networkProtocol;
    IMobility* mobility = nullptr;
    UdpSocket socket;

    // Strategy submodules (sibling submodules of the compound Gzrp module).
    // The pointers are suffixed -Strategy because `gate` collides with the
    // cModule::gate(const char*) accessor; the NED submodule names used in
    // the .ini stay as scoring/decay/gate/threshold.
    IScoringStrategy* scoringStrategy = nullptr;
    IDecayStrategy* decayStrategy = nullptr;
    IGateStrategy* gateStrategy = nullptr;
    IThresholdStrategy* thresholdStrategy = nullptr;

    // Parameters (only the core knobs remain; strategy-specific values live
    // on the strategy submodules).
    simtime_t linkStateLifetime = 3;
    simtime_t IARP_updateInterval = 3;
    bool enableOriginatorPreDecay = true;
    // EMA smoothing factor applied in handleNDPHello to the raw per-link
    // quality returned by the scoring strategy. Kept at the core (not in
    // the strategy) because it is orthogonal to "how is a single link
    // scored"; the scoring strategy returns a fresh sample, the core
    // smooths it across samples. Mirrors SAZRP::emaAlpha; first sample
    // from a neighbour seeds the EMA directly.
    double emaAlpha = 0.3;
    // ROUTE_REPLY install arbitration policy. "last-wins" (classic ZRP):
    // every reply unconditionally replaces the installed IERP route. The
    // bool below caches the parsed parameter; the default false matches
    // the NED default of "stability-hops" (SAZRP/GZRP-Sazrp tiebreak).
    bool ierpReplyInstallLastWins = false;
    unsigned int zrpUDPPort = 0;
    simtime_t NDP_helloInterval = 3;
    simtime_t debugInterval = 0;
    simtime_t brpJitterMax = 0.1;
    simtime_t brpCoverageLifetime = 30;
    simtime_t ierpRetryInterval = 3;
    unsigned int ierpMaxRetries = 3;
    simtime_t delayedPacketLifetime = 5;
    double IARP_eventDelay = 500;
    double IARP_eventJitter = 15;

    // NDP/IARP state
    uint16_t NDP_seqNum = 0;
    uint16_t IARP_seqNum = 0;
    // Unified neighbour map -- replaces SAZRP's (neighbourTable,
    // neighbourStability, neighbourKinematics) triple. Strategy-owned fields
    // (lastPos, lastVel) live in NeighbourState; the Gzrp core itself only
    // reads addr/lastHeard/quality.
    std::map<L3Address, NeighbourState> neighbours;
    std::map<L3Address, LinkStateEntry> linkStateTable;

    // IERP
    uint16_t IERP_queryId = 0;
    std::map<IerpQueryId, IerpQueryRecord> ierpQueryTable;
    std::multimap<L3Address, std::pair<simtime_t, Packet*>> delayedPackets;
    std::map<L3Address, cMessage*> ierpRetryTimers;
    std::map<L3Address, int> ierpRetryCounters;
    std::map<L3Address, simtime_t> ierpDiscoveryStartTimes;

    // BRP
    uint16_t BRP_bordercastId = 0;
    struct BrpQueryCoverage {
        IerpQueryId queryId;
        int brpCacheId;
        std::set<L3Address> coveredNodes;
        simtime_t createTime;
        bool delivered;
    };
    std::map<int, BrpQueryCoverage> brpCoverageTable;
    std::vector<cMessage*> pendingTimers;

    cMessage* NDP_helloTimer = nullptr;
    cMessage* IARP_updateTimer = nullptr;
    cMessage* debugTimer = nullptr;

    bool iarpUpdatePending = false;

  protected:
    void handleMessageWhenUp(cMessage* msg) override;
    void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void refreshDisplay() const override;

    virtual void handleStartOperation(LifecycleOperation* operation) override;
    virtual void handleStopOperation(LifecycleOperation* operation) override;
    virtual void handleCrashOperation(LifecycleOperation* operation) override;

    virtual Result datagramPreRoutingHook(Packet* datagram) override;
    virtual Result datagramForwardHook(Packet* datagram) override;
    virtual Result datagramPostRoutingHook(Packet* datagram) override;
    virtual Result datagramLocalInHook(Packet* datagram) override;
    virtual Result datagramLocalOutHook(Packet* datagram) override;

    virtual void socketDataArrived(UdpSocket* socket, Packet* packet) override;
    virtual void socketErrorArrived(UdpSocket* socket, Indication* indication) override;
    virtual void socketClosed(UdpSocket* socket) override;

    virtual void receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details) override;

    // Helpers
    L3Address getSelfIPAddress() const;
    int getNumIarpRoutes() const;
    void clearState();
    void printDebugTables();
    void processPacket(Packet* packet);
    void sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl);

    // Build a fully-resolved SelfState for the local node. The threshold
    // module is called once with a SelfState whose threshold field is 0
    // (this bootstrap value is documented in IStrategy.h's SelfState).
    SelfState buildSelfState() const;
    // Build a SelfState representing a remote forwarder `u` (a node visible
    // via linkStateTable) as if `u` were the local node. The temporary
    // NeighbourState map is populated into `tmpOut` and borrowed by the
    // returned SelfState, so `tmpOut` must outlive the SelfState use.
    SelfState buildSelfStateFor(const L3Address& u, double tau,
                                std::map<L3Address, NeighbourState>& tmpOut) const;

    // NDP
    const Ptr<NDP_Hello> createNDPHello();
    void sendNDPHello();
    void handleNDPHello(const Ptr<NDP_Hello>& hello, const L3Address& sourceAddr);
    void NDP_refreshNeighbourTable();

    // IARP
    const Ptr<IARP_LinkStateUpdate> createIARPUpdate();
    void sendIARPUpdate();
    void scheduleEarlyIARPUpdate();
    void handleIARPUpdate(const Ptr<IARP_LinkStateUpdate>& update, const L3Address& sourceAddr);
    void IARP_refreshLinkStateTable();
    void IARP_updateRoutingTable();
    void IARP_purgeRoutingTable();
    void IARP_computeRoutes();
    IRoute* IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                             const std::vector<L3Address>& fullRoute);

    // IERP
    void IERP_initiateRouteDiscovery(const L3Address& dest, bool isRetry = false);
    const Ptr<IERP_RouteData> IERP_createRouteRequest(const L3Address& dest);
    const Ptr<IERP_RouteData> IERP_createRouteReply(const Ptr<IERP_RouteData>& request);
    void IERP_handleRouteRequest(const Ptr<IERP_RouteData>& request, const L3Address& sourceAddr);
    void IERP_handleRouteReply(const Ptr<IERP_RouteData>& reply, const L3Address& sourceAddr);
    void IERP_routeMaintenance();
    IRoute* IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                             const std::vector<L3Address>& fullRoute);
    void IERP_purgeRoutingTable();
    bool IERP_hasRouteToDestination(const L3Address& dest) const;
    IRoute* IERP_findRoute(const L3Address& dest) const;
    bool IERP_hasOngoingDiscovery(const L3Address& dest) const;
    void IERP_delayDatagram(Packet* datagram);
    void IERP_completeRouteDiscovery(const L3Address& dest);
    bool IERP_isQuerySeen(const IerpQueryId& qid) const;
    void IERP_recordQuery(const IerpQueryId& qid, const L3Address& dest);
    void IERP_cleanQueryTable();

    // BRP
    void BRP_bordercast(const Ptr<IERP_RouteData>& packet);
    void BRP_deliver(const Ptr<BRP_Data>& brpPacket, const L3Address& sourceAddr);
    std::set<L3Address> BRP_getMyZone() const;
    std::set<L3Address> BRP_getMyPeripherals() const;
    std::set<L3Address> BRP_getOutNeighbours(const std::set<L3Address>& uncoveredPeripherals) const;
    bool BRP_isOutNeighbour(const L3Address& prevBordercaster, const L3Address& node,
                           const std::set<L3Address>& coveredNodes, std::set<L3Address>& outPrevZone) const;
    void BRP_recordCoverage(int brpCacheId, const std::set<L3Address>& nodes);
    int BRP_findOrCreateCoverage(const IerpQueryId& qid);
    void BRP_cleanCoverageTable();

    void schedulePendingTimer(cMessage* msg, simtime_t delay);
    void cancelPendingTimer(cMessage* msg);
    void cancelAllPendingTimers();

  public:
    Gzrp();
    virtual ~Gzrp();
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_H_
