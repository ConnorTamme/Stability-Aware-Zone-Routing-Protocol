//
// Main file of the GZRP (Generalised ZRP) implementation. Structurally a
// port of SAZRP, with the four logical decisions (scoring, decay, gate,
// threshold) delegated to swappable strategy submodules.
//

#include "Gzrp.h"
#include "GzrpRouteData.h"

#include <sstream>
#include <iomanip>
#include <set>
#include <algorithm>
#include <queue>
#include <cmath>
#include <limits>
#include <fstream>
#include <cstdlib>

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/Simsignals.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/stlutils.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/networklayer/ipv4/IcmpHeader.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4Route.h"
#include "inet/transportlayer/common/L4PortTag_m.h"

namespace inet {
namespace gzrp {

// Diagnostic dump (parity hunt with Zrp.cc). Same format as Zrp::DIAG_LOG so
// the two protocols' logs can be byte-compared. Gated on env var ZRP_DIAG_FILE.
namespace {
std::ofstream& diagStream()
{
    static std::ofstream s;
    static bool checked = false;
    if (!checked) {
        checked = true;
        const char* path = std::getenv("ZRP_DIAG_FILE");
        if (path && *path) s.open(path);
    }
    return s;
}
inline bool diagEnabled() { return diagStream().is_open(); }
} // namespace
#define DIAG_LOG(node, body) do { if (diagEnabled()) { \
    diagStream() << std::fixed << std::setprecision(9) << simTime().dbl() \
                 << " " << (node)->getFullName() << " " << body << std::endl; } } while (0)

Define_Module(Gzrp);

simsignal_t Gzrp::controlPacketSentSignal = registerSignal("controlPacketSent");
simsignal_t Gzrp::routeDiscoveryStartedSignal = registerSignal("routeDiscoveryStarted");
simsignal_t Gzrp::routeDiscoveryRetriedSignal = registerSignal("routeDiscoveryRetried");
simsignal_t Gzrp::pktSentNDPSignal       = registerSignal("pktSentNDP");
simsignal_t Gzrp::pktSentIARPSignal      = registerSignal("pktSentIARP");
simsignal_t Gzrp::pktSentIERPQuerySignal = registerSignal("pktSentIERPQuery");
simsignal_t Gzrp::pktSentIERPReplySignal = registerSignal("pktSentIERPReply");
simsignal_t Gzrp::pktSentBRPSignal       = registerSignal("pktSentBRP");
simsignal_t Gzrp::routeLengthSignal       = registerSignal("routeLength");
simsignal_t Gzrp::routeDiscoveryTimeSignal = registerSignal("routeDiscoveryTime");

namespace {
// Threshold below which a link is treated as effectively absent by the
// Dijkstra relaxation. Carried over from SAZRP for parity.
constexpr double STABILITY_EPSILON = 1e-6;
} // namespace

Gzrp::Gzrp() {}

Gzrp::~Gzrp()
{
    // Mirrors SAZRP: clearState() on dtor was erroring out, and the
    // experiments do not reuse modules, so we leave cleanup to handleStop.
}

void Gzrp::initialize(int stage)
{
    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        networkProtocol->registerHook(0, this);
        host->subscribe(linkBrokenSignal, this);
    }

    if (stage == INITSTAGE_LOCAL) {
        host = getContainingNode(this);

        routingTable.reference(this, "routingTableModule", true);
        interfaceTable.reference(this, "interfaceTableModule", true);
        networkProtocol.reference(this, "networkProtocolModule", true);

        mobility = check_and_cast<IMobility*>(host->getSubmodule("mobility"));

        // Resolve strategy submodules. They live as siblings of this simple
        // module under the compound Gzrp container in Gzrp.ned.
        cModule* container = getParentModule();
        scoringStrategy   = check_and_cast<IScoringStrategy*>(container->getSubmodule("scoring"));
        decayStrategy     = check_and_cast<IDecayStrategy*>(container->getSubmodule("decay"));
        gateStrategy      = check_and_cast<IGateStrategy*>(container->getSubmodule("gate"));
        thresholdStrategy = check_and_cast<IThresholdStrategy*>(container->getSubmodule("threshold"));

        NDP_helloTimer = new cMessage("NDP_helloTimer");
        IARP_updateTimer = new cMessage("IARP_updateTimer");
        debugTimer = new cMessage("debugTimer");

        zrpUDPPort = par("udpPort");
        NDP_helloInterval = par("NDP_helloInterval");
        IARP_updateInterval = par("IARP_updateInterval");
        enableOriginatorPreDecay = par("enableOriginatorPreDecay");
        emaAlpha = par("emaAlpha");
        {
            std::string policy = par("ierpReplyInstallPolicy").stdstringValue();
            if (policy == "last-wins") {
                ierpReplyInstallLastWins = true;
            }
            else if (policy == "stability-hops") {
                ierpReplyInstallLastWins = false;
            }
            else {
                throw cRuntimeError("Gzrp: ierpReplyInstallPolicy must be \"last-wins\" or "
                                    "\"stability-hops\", got \"%s\"", policy.c_str());
            }
        }
        linkStateLifetime = par("linkStateLifetime");
        debugInterval = par("debugInterval");
        brpJitterMax = par("brpJitterMax");
        brpCoverageLifetime = par("brpCoverageLifetime");
        ierpRetryInterval = par("ierpRetryInterval");
        ierpMaxRetries = par("ierpMaxRetries");
        delayedPacketLifetime = par("delayedPacketLifetime");
        IARP_eventDelay = par("IARP_eventDelay");
        IARP_eventJitter = par("IARP_eventJitter");

        WATCH(enableOriginatorPreDecay);
        WATCH(NDP_seqNum);
        WATCH(IARP_seqNum);
        WATCH_MAP(neighbours);
        WATCH_MAP(linkStateTable);
        WATCH(IERP_queryId);
    }
}

void Gzrp::handleMessageWhenUp(cMessage* msg)
{
    if (msg->isSelfMessage()) {
        if (msg == NDP_helloTimer) {
            NDP_refreshNeighbourTable();
            sendNDPHello();
        }
        else if (msg == IARP_updateTimer) {
            IARP_refreshLinkStateTable();
            sendIARPUpdate();
            IERP_cleanQueryTable();
            BRP_cleanCoverageTable();
        }
        else if (msg == debugTimer) {
            printDebugTables();
            if (debugInterval > 0)
                scheduleAfter(debugInterval, debugTimer);
        }
        else if (msg->getKind() == GZRP_SELF_IERP_RETRY) {
            L3Address dest = L3Address(Ipv4Address(msg->par("destAddr").longValue()));
            EV_INFO << "IERP retry timer for " << dest << endl;

            auto tmrIt = ierpRetryTimers.find(dest);
            if (tmrIt != ierpRetryTimers.end() && tmrIt->second == msg) {
                ierpRetryTimers.erase(tmrIt);
            }

            if (!routingTable->findBestMatchingRoute(dest) && delayedPackets.count(dest) > 0) {
                auto retryIt = ierpRetryCounters.find(dest);
                int retryCount = (retryIt != ierpRetryCounters.end()) ? retryIt->second : 0;

                if (retryCount < (int)ierpMaxRetries) {
                    ierpRetryCounters[dest] = retryCount + 1;
                    EV_INFO << "IERP: Retrying route discovery for " << dest << " (attempt " << (retryCount + 1) << "/"
                            << ierpMaxRetries << ")" << endl;

                    L3Address self = getSelfIPAddress();
                    for (auto it = ierpQueryTable.begin(); it != ierpQueryTable.end();) {
                        if (it->first.source == self && it->second.destination == dest && !it->second.replied) {
                            it = ierpQueryTable.erase(it);
                        }
                        else {
                            ++it;
                        }
                    }

                    IERP_initiateRouteDiscovery(dest, /*isRetry=*/true);
                }
                else {
                    EV_WARN << "IERP: Max retries (" << ierpMaxRetries << ") exhausted for " << dest << ", dropping "
                            << delayedPackets.count(dest) << " buffered packets" << endl;
                    auto lt = delayedPackets.lower_bound(dest);
                    auto ut = delayedPackets.upper_bound(dest);
                    for (auto it = lt; it != ut; it++) {
                        networkProtocol->dropQueuedDatagram(it->second.second);
                    }
                    delayedPackets.erase(lt, ut);
                    ierpRetryCounters.erase(dest);
                    ierpDiscoveryStartTimes.erase(dest);
                }
            }
            else {
                ierpRetryCounters.erase(dest);
            }

            delete msg;
        }
        else if (msg->getKind() == GZRP_SELF_BRP_JITTER) {
            int brpCacheId = (int)msg->par("brpCacheId").longValue();
            auto* brpDataRaw = static_cast<BRP_Data*>(msg->getContextPointer());

            if (brpDataRaw) {
                const auto& encapIerp = brpDataRaw->getEncapsulatedPacket();
                auto ierpCopy = makeShared<IERP_RouteData>();
                ierpCopy->setType(encapIerp.getType());
                ierpCopy->setLength(encapIerp.getLength());
                ierpCopy->setNodePtr(encapIerp.getNodePtr());
                ierpCopy->setQueryID(encapIerp.getQueryID());
                ierpCopy->setSourceAddr(encapIerp.getSourceAddr());
                ierpCopy->setDestAddr(encapIerp.getDestAddr());
                ierpCopy->setIntermediateNodesArraySize(encapIerp.getIntermediateNodesArraySize());
                for (size_t i = 0; i < encapIerp.getIntermediateNodesArraySize(); i++)
                    ierpCopy->setIntermediateNodes(i, encapIerp.getIntermediateNodes(i));
                ierpCopy->setChunkLength(encapIerp.getChunkLength());

                L3Address sourceAddr = brpDataRaw->getPrevBordercastAddr();

                EV_INFO << "BRP jitter expired: delivering IERP packet (queryID=" << ierpCopy->getQueryID()
                        << ", cacheId=" << brpCacheId << ") to IERP" << endl;

                uint8_t type = ierpCopy->getType();
                if (type == IERP_QUERY) {
                    IERP_handleRouteRequest(ierpCopy, sourceAddr);
                }
                else if (type == IERP_REPLY) {
                    IERP_handleRouteReply(ierpCopy, sourceAddr);
                }

                delete brpDataRaw;
            }

            auto it = std::find(pendingTimers.begin(), pendingTimers.end(), msg);
            if (it != pendingTimers.end())
                pendingTimers.erase(it);
            delete msg;
        }
        else {
            throw cRuntimeError("Unknown self message: %s", msg->getName());
        }
    }
    else {
        socket.processMessage(msg);
    }
}

void Gzrp::handleStartOperation(LifecycleOperation* operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(L3Address(), zrpUDPPort);
    socket.setBroadcast(true);

    scheduleAfter(uniform(0, 0.1), NDP_helloTimer);
    scheduleAfter(NDP_helloInterval * 2 + uniform(0, 0.5), IARP_updateTimer);

    if (debugInterval > 0)
        scheduleAfter(debugInterval, debugTimer);
}

void Gzrp::handleStopOperation(LifecycleOperation* operation)
{
    clearState();
}

void Gzrp::handleCrashOperation(LifecycleOperation* operation)
{
    clearState();
}

void Gzrp::clearState()
{
    cancelAndDelete(NDP_helloTimer);
    NDP_helloTimer = nullptr;
    cancelAndDelete(IARP_updateTimer);
    IARP_updateTimer = nullptr;
    cancelAndDelete(debugTimer);
    debugTimer = nullptr;

    cancelAllPendingTimers();

    for (auto& entry : delayedPackets) {
        delete entry.second.second;
    }
    delayedPackets.clear();

    for (auto& entry : ierpRetryTimers) {
        cancelAndDelete(entry.second);
    }
    ierpRetryTimers.clear();

    neighbours.clear();
    linkStateTable.clear();
    ierpQueryTable.clear();
    brpCoverageTable.clear();
    ierpDiscoveryStartTimes.clear();

    NDP_seqNum = 0;
    IARP_seqNum = 0;
    IERP_queryId = 0;
    BRP_bordercastId = 0;

    if (routingTable != nullptr && routingTable.getNullable() != nullptr) {
        IARP_purgeRoutingTable();
        IERP_purgeRoutingTable();
    }
}

void Gzrp::printDebugTables()
{
    std::ostringstream os;

    os << "\n";
    os << "========================================================================\n";
    os << "  GZRP DEBUG OUTPUT - Node: " << getSelfIPAddress() << " @ t=" << simTime() << "\n";
    os << "========================================================================\n";

    os << "\n  NEIGHBOR TABLE (" << neighbours.size() << " entries):\n";
    os << "  +-----------------+------------------+--------------+----------+\n";
    os << "  | Neighbour       | Last Heard       | Age (sec)    | quality  |\n";
    os << "  +-----------------+------------------+--------------+----------+\n";
    if (neighbours.empty()) {
        os << "  |            (empty)                                          |\n";
    }
    else {
        for (const auto& entry : neighbours) {
            double age = (simTime() - entry.second.lastHeard).dbl();
            os << "  | " << std::setw(15) << std::left << entry.first.str() << " | " << std::setw(16) << entry.second.lastHeard
               << " | " << std::setw(12) << std::fixed << std::setprecision(2) << age
               << " | " << std::setw(8) << std::fixed << std::setprecision(3) << entry.second.quality << " |\n";
        }
    }
    os << "  +-----------------+------------------+--------------+----------+\n";

    os << "\n  LINK STATE TABLE (" << linkStateTable.size() << " entries):\n";
    if (linkStateTable.empty()) {
        os << "    (empty)\n";
    }
    else {
        for (const auto& entry : linkStateTable) {
            const LinkStateEntry& ls = entry.second;
            double age = (simTime() - ls.insertTime).dbl();
            os << "  +-- Source: " << ls.sourceAddr.str() << " (seq=" << ls.seqNum
               << ", age=" << std::fixed << std::setprecision(1) << age << "s)\n";
            os << "  |   Neighbours (" << ls.linkDestinations.size() << "):\n";
            for (const auto& dest : ls.linkDestinations) {
                os << "  |     -> " << dest.destAddr.str();
                if (IARP_METRIC_COUNT > 0) {
                    os << " [metric=" << dest.metrics[0] << "]";
                }
                os << "\n";
            }
        }
    }

    os << "\n  ROUTING TABLE (IARP routes):\n";
    os << "  +-----------------+-----------------+----------+\n";
    os << "  | Destination     | Next Hop        | Hops     |\n";
    os << "  +-----------------+-----------------+----------+\n";
    int routeCount = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            routeCount++;
            os << "  | " << std::setw(15) << std::left << route->getDestinationAsGeneric().str() << " | "
               << std::setw(15) << route->getNextHopAsGeneric().str() << " | " << std::setw(8) << route->getMetric()
               << " |\n";
        }
    }
    if (routeCount == 0) {
        os << "  |        (no IARP routes installed)          |\n";
    }
    os << "  +-----------------+-----------------+----------+\n";
    os << "  Total IARP routes: " << routeCount << "\n";

    os << "========================================================================\n\n";

    EV_INFO << os.str();
}

INetfilter::IHook::Result Gzrp::datagramPreRoutingHook(Packet* datagram)
{
    Enter_Method("datagramPreRoutingHook");
    return ACCEPT;
}

INetfilter::IHook::Result Gzrp::datagramForwardHook(Packet* datagram)
{
    Enter_Method("datagramForwardHook");
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    L3Address destAddr = networkHeader->getDestinationAddress();

    if (!destAddr.isBroadcast() && !destAddr.isMulticast() && destAddr != getSelfIPAddress()) {
        IRoute* route = routingTable->findBestMatchingRoute(destAddr);
        if (!route) {
            EV_INFO << "Forward hook: No route to " << destAddr << ", buffering and initiating IERP discovery" << endl;
            IERP_delayDatagram(datagram);
            if (!IERP_hasOngoingDiscovery(destAddr)) {
                IERP_initiateRouteDiscovery(destAddr);
            }
            return QUEUE;
        }
    }
    return ACCEPT;
}

INetfilter::IHook::Result Gzrp::datagramPostRoutingHook(Packet* datagram)
{
    Enter_Method("datagramPostRoutingHook");
    return ACCEPT;
}

INetfilter::IHook::Result Gzrp::datagramLocalInHook(Packet* datagram)
{
    Enter_Method("datagramLocalInHook");
    return ACCEPT;
}

INetfilter::IHook::Result Gzrp::datagramLocalOutHook(Packet* datagram)
{
    Enter_Method("datagramLocalOutHook");
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    L3Address destAddr = networkHeader->getDestinationAddress();

    if (!destAddr.isBroadcast() && !destAddr.isMulticast() && destAddr != getSelfIPAddress()) {
        IRoute* route = routingTable->findBestMatchingRoute(destAddr);
        if (!route) {
            EV_INFO << "No route to " << destAddr << ", buffering datagram and initiating IERP route discovery" << endl;

            IERP_delayDatagram(datagram);

            if (!IERP_hasOngoingDiscovery(destAddr)) {
                IERP_initiateRouteDiscovery(destAddr);
            }
            else {
                EV_DETAIL << "Route discovery already in progress for " << destAddr << endl;
            }

            return QUEUE;
        }
    }
    return ACCEPT;
}

void Gzrp::socketDataArrived(UdpSocket* socket, Packet* packet)
{
    processPacket(packet);
}

void Gzrp::socketErrorArrived(UdpSocket* socket, Indication* indication)
{
    EV_WARN << "UDP socket error" << endl;
    delete indication;
}

void Gzrp::socketClosed(UdpSocket* socket) {}

void Gzrp::receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details)
{
    Enter_Method("receiveSignal");
    if (signalID == linkBrokenSignal) {
        Packet* datagram = check_and_cast<Packet*>(obj);
        const auto& networkHeader = findNetworkProtocolHeader(datagram);
        if (networkHeader != nullptr) {
            L3Address unreachableDest = networkHeader->getDestinationAddress();
            IRoute* failedRoute = routingTable->findBestMatchingRoute(unreachableDest);
            if (failedRoute == nullptr || failedRoute->getSource() != this) {
                EV_DETAIL << "Link break for " << unreachableDest
                          << " but no GZRP route found; ignoring" << endl;
                return;
            }
            L3Address unreachableNextHop = failedRoute->getNextHopAsGeneric();
            EV_WARN << "Link break detected to next hop " << unreachableNextHop
                    << " (final dest " << unreachableDest << ")" << endl;

            auto it = neighbours.find(unreachableNextHop);
            if (it != neighbours.end()) {
                neighbours.erase(it);
                EV_INFO << "Removed broken neighbour " << unreachableNextHop << " from neighbour table" << endl;
            }

            for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
                IRoute* route = routingTable->getRoute(i);
                if (route->getSource() == this && route->getNextHopAsGeneric() == unreachableNextHop) {
                    L3Address dest = route->getDestinationAsGeneric();
                    EV_WARN << "Removing broken route to " << dest << " via " << unreachableNextHop << endl;
                    routingTable->deleteRoute(route);
                }
            }

            IARP_updateRoutingTable();
            IERP_routeMaintenance();
        }
    }
}

void Gzrp::refreshDisplay() const
{
    RoutingProtocolBase::refreshDisplay();

    int numRoutes = getNumIarpRoutes();
    int numNeighbours = neighbours.size();
    int numIerpRoutes = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                numIerpRoutes++;
            }
        }
    }

    char buf[80];
    sprintf(buf, "N:%d IA:%d IE:%d", numNeighbours, numRoutes, numIerpRoutes);
    getDisplayString().setTagArg("t", 0, buf);
}

int Gzrp::getNumIarpRoutes() const
{
    int count = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        if (routingTable->getRoute(i)->getSource() == this) {
            count++;
        }
    }
    return count;
}

L3Address Gzrp::getSelfIPAddress() const
{
    return routingTable->getRouterIdAsGeneric();
}

SelfState Gzrp::buildSelfState() const
{
    SelfState s;
    s.neighbours = &neighbours;
    // Only query mobility if the scoring strategy actually reads pos/vel.
    // Every call to mobility->getCurrentPosition() routes through
    // MovingMobilityBase::moveAndUpdate(), which on first-of-simtime calls
    // updates lastUpdate and emits mobilityStateChangedSignal. ZRP never
    // touches mobility, so for GZRP-Classic (ConstantOneScore) skipping the
    // query keeps GZRP's event stream aligned with ZRP's. LparStabilityScore
    // overrides needsKinematics() to true; SAZRP-mode paths get the live
    // pos/vel they actually use.
    if (scoringStrategy->needsKinematics()) {
        s.pos = mobility->getCurrentPosition();
        s.vel = mobility->getCurrentVelocity();
    }
    // Bootstrap: ask threshold module with a partial SelfState whose
    // threshold field is 0. Threshold strategies that don't depend on
    // self info ignore the field; ones that do must tolerate the zero
    // (documented in IStrategy.h).
    s.threshold = thresholdStrategy->threshold(s);
    return s;
}

SelfState Gzrp::buildSelfStateFor(const L3Address& u, double tau,
                                  std::map<L3Address, NeighbourState>& tmpOut) const
{
    SelfState s;
    s.threshold = tau;
    auto it = linkStateTable.find(u);
    if (it != linkStateTable.end()) {
        for (const auto& ld : it->second.linkDestinations) {
            NeighbourState ns;
            ns.addr = ld.destAddr;
            ns.quality = decodeStability(static_cast<uint8_t>(ld.metrics[0] & 0xFF));
            tmpOut[ld.destAddr] = ns;
        }
    }
    s.neighbours = &tmpOut;
    // pos/vel left default; they are not consulted by gate/decay strategies
    // when this SelfState represents a remote forwarder in the Dijkstra.
    return s;
}

void Gzrp::processPacket(Packet* packet)
{
    L3Address sourceAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
    auto chunk = packet->peekAtFront<FieldsChunk>();

    if (auto ndpHello = dynamicPtrCast<const NDP_Hello>(chunk)) {
        handleNDPHello(CHK(dynamicPtrCast<NDP_Hello>(chunk->dupShared())), sourceAddr);
    }
    else if (auto iarpUpdate = dynamicPtrCast<const IARP_LinkStateUpdate>(chunk)) {
        handleIARPUpdate(CHK(dynamicPtrCast<IARP_LinkStateUpdate>(chunk->dupShared())), sourceAddr);
    }
    else if (auto ierpPacket = dynamicPtrCast<const IERP_RouteData>(chunk)) {
        auto mutableIerp = CHK(dynamicPtrCast<IERP_RouteData>(chunk->dupShared()));
        uint8_t type = mutableIerp->getType();
        if (type == IERP_QUERY) {
            IERP_handleRouteRequest(mutableIerp, sourceAddr);
        }
        else if (type == IERP_REPLY) {
            IERP_handleRouteReply(mutableIerp, sourceAddr);
        }
        else {
            EV_WARN << "Unknown IERP packet type: " << (int)type << endl;
        }
    }
    else if (auto brpPacket = dynamicPtrCast<const BRP_Data>(chunk)) {
        auto mutableBrp = CHK(dynamicPtrCast<BRP_Data>(chunk->dupShared()));
        BRP_deliver(mutableBrp, sourceAddr);
    }
    else {
        EV_WARN << "Unknown GZRP packet type received" << endl;
    }

    delete packet;
}

void Gzrp::sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl)
{
    const char* className = payload->getClassName();
    Packet* packet = new Packet(!strncmp("inet::", className, 6) ? className + 6 : className, payload);

    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId();

    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<HopLimitReq>()->setHopLimit(ttl);
    packet->addTag<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTag<L4PortReq>()->setDestPort(zrpUDPPort);

    emit(controlPacketSentSignal, packet);
    if (dynamicPtrCast<const NDP_Hello>(payload))
        emit(pktSentNDPSignal, packet);
    else if (dynamicPtrCast<const IARP_LinkStateUpdate>(payload))
        emit(pktSentIARPSignal, packet);
    else if (auto ierp = dynamicPtrCast<const IERP_RouteData>(payload))
        emit(ierp->getType() == IERP_QUERY ? pktSentIERPQuerySignal : pktSentIERPReplySignal,
             packet);
    else if (dynamicPtrCast<const BRP_Data>(payload))
        emit(pktSentBRPSignal, packet);
    socket.send(packet);
}

// NDP

const Ptr<NDP_Hello> Gzrp::createNDPHello()
{
    auto hello = makeShared<NDP_Hello>();

    hello->setNodeAddress(getSelfIPAddress());
    hello->setSeqNum(NDP_seqNum++);

    size_t extLen = scoringStrategy->helloExtensionLength();
    hello->setHelloExtensionArraySize(extLen);
    scoringStrategy->populateHelloExtension(hello.get(), buildSelfState());

    // Wire size = L3Address(4) + seqNum(2) + helloExtension(extLen)
    hello->setChunkLength(B(4 + 2 + extLen));

    return hello;
}

void Gzrp::sendNDPHello()
{
    EV_INFO << "Sending NDP Hello from " << getSelfIPAddress() << endl;

    auto hello = createNDPHello();
    sendZrpPacket(hello, Ipv4Address::ALLONES_ADDRESS, 1);

    scheduleAfter(NDP_helloInterval, NDP_helloTimer);
}

void Gzrp::handleNDPHello(const Ptr<NDP_Hello>& hello, const L3Address& sourceAddr)
{
    EV_INFO << "Received NDP Hello from " << sourceAddr << " (node address: " << hello->getNodeAddress()
            << ", seq: " << hello->getSeqNum() << ")" << endl;

    bool isNewNeighbour = (neighbours.find(sourceAddr) == neighbours.end());

    NeighbourState& ns = neighbours[sourceAddr];
    ns.addr = sourceAddr;
    ns.lastHeard = simTime();
    DIAG_LOG(host, "NDP_RECV from=" << sourceAddr << " seq=" << hello->getSeqNum()
                                    << " new=" << (isNewNeighbour ? 1 : 0));

    // Strategy fills any scoring-specific fields (kinematics for LPAR, none
    // for ConstantOne) from the wire extension, scores the link, and we
    // EMA-smooth the sample across observations. First sample from a
    // neighbour seeds the EMA directly (mirrors SAZRP's hadStability path).
    scoringStrategy->parseHelloExtension(hello.get(), ns);
    double rawScore = scoringStrategy->scoreLink(buildSelfState(), ns);
    if (isNewNeighbour) {
        ns.quality = rawScore;
    }
    else {
        ns.quality = emaAlpha * rawScore + (1.0 - emaAlpha) * ns.quality;
    }

    EV_DETAIL << "Neighbour table now has " << neighbours.size() << " entries; "
              << sourceAddr << " quality=" << ns.quality << endl;

    if (isNewNeighbour) {
        EV_INFO << "New neighbour " << sourceAddr << " discovered, recomputing IARP routes" << endl;
        IARP_updateRoutingTable();
        scheduleEarlyIARPUpdate();
    }
}

void Gzrp::NDP_refreshNeighbourTable()
{
    EV_INFO << "Refreshing neighbour table..." << endl;

    simtime_t now = simTime();
    std::vector<L3Address> toRemove;

    for (const auto& entry : neighbours) {
        if (now - entry.second.lastHeard > linkStateLifetime) {
            toRemove.push_back(entry.first);
        }
    }

    for (const auto& addr : toRemove) {
        neighbours.erase(addr);
        DIAG_LOG(host, "NDP_STALE addr=" << addr);
        EV_DETAIL << "Removed stale neighbour: " << addr << endl;
    }

    EV_INFO << "Neighbour table refresh complete, " << neighbours.size() << " neighbours remain" << endl;

    if (!toRemove.empty()) {
        IARP_updateRoutingTable();
        scheduleEarlyIARPUpdate();
    }
}

// IARP

const Ptr<IARP_LinkStateUpdate> Gzrp::createIARPUpdate()
{
    auto update = makeShared<IARP_LinkStateUpdate>();

    SelfState self = buildSelfState();

    update->setSourceAddr(getSelfIPAddress());
    update->setSeqNum(IARP_seqNum++);
    update->setRadius(0);

    // Wire byte: decay strategy's initial value, then optionally pre-decayed
    // one hop at the source (the classic-ZRP TTL = R - 1 analogue when the
    // decay is a per-node multiplicative beta; a no-op for hop-count decays).
    uint8_t initial = decayStrategy->initialState(self);
    uint8_t runningByte = enableOriginatorPreDecay ? decayStrategy->decayState(initial, self) : initial;
    update->setRunningStability(runningByte);

    size_t neighbourCount = neighbours.size();
    update->setLinkDestCount(neighbourCount);
    update->setLinkDestDataArraySize(neighbourCount);

    size_t idx = 0;
    for (const auto& neighbour : neighbours) {
        IARP_LinkDestData destData;
        destData.addr = neighbour.first;

        // Per-link metric is the quantised quality returned by the scoring
        // strategy. For LparStabilityScore this is the D*Y per-link sample;
        // for ConstantOneScore it is always 255.
        uint8_t q = encodeStability(neighbour.second.quality);
        for (int m = 0; m < IARP_METRIC_COUNT; m++) {
            destData.metrics[m].metricType = IARP_METRIC_STABILITY;
            destData.metrics[m].metricValue = static_cast<uint16_t>(q);
        }

        update->setLinkDestData(idx++, destData);
    }

    B chunkLength = B(12 + neighbourCount * (4 + IARP_METRIC_COUNT * 4));
    update->setChunkLength(chunkLength);

    return update;
}

void Gzrp::sendIARPUpdate()
{
    EV_INFO << "Sending IARP Link State Update from " << getSelfIPAddress() << " with " << neighbours.size()
            << " neighbours" << endl;

    if (neighbours.empty()) {
        EV_DETAIL << "No neighbours to advertise, skipping IARP update" << endl;
        iarpUpdatePending = false;
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }

    SelfState self = buildSelfState();

    // Originator gate: only "throw the grenade" if the gate strategy says so.
    // AlwaysAdmitGate is the classic-ZRP no-op; FractionGoodGate is the SAZRP
    // fringe filter.
    if (!gateStrategy->nodePassesGate(self, self.threshold)) {
        EV_DETAIL << "Suppressing IARP update: gate strategy rejected (fringe node)" << endl;
        iarpUpdatePending = false;
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }

    // Admissibility short-circuit: if no receiver would admit the byte we
    // are about to emit, the send is pure waste. This is the generalised
    // analogue of classic ZRP's "skip IARP when zoneRadius <= 1" rule --
    // for StepDecay(radius=1) with enableOriginatorPreDecay=true, the
    // emitted byte (2) is already past the radius gate (2 > 1) and every
    // receiver would drop it on arrival. For multiplicative-beta decay the
    // check fires symmetrically when the initial value is already below
    // tau (e.g. badly-tuned betaMin/tau combos), turning a guaranteed-drop
    // broadcast into a no-op rather than burning radio time.
    uint8_t originatorInitial = decayStrategy->initialState(self);
    uint8_t originatorByte = enableOriginatorPreDecay
                             ? decayStrategy->decayState(originatorInitial, self)
                             : originatorInitial;
    if (!decayStrategy->isAdmissible(originatorByte, self.threshold)) {
        EV_DETAIL << "Suppressing IARP update: nobody would admit the originator byte "
                  << (int)originatorByte << " (tau=" << self.threshold << ")" << endl;
        iarpUpdatePending = false;
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }

    auto update = createIARPUpdate();
    DIAG_LOG(host, "IARP_SEND seq=" << update->getSeqNum() << " nbrs=" << neighbours.size());
    sendZrpPacket(update, Ipv4Address::ALLONES_ADDRESS, 255);

    iarpUpdatePending = false;
    scheduleAfter(IARP_updateInterval, IARP_updateTimer);
}

void Gzrp::scheduleEarlyIARPUpdate()
{
    if (iarpUpdatePending)
        return;
    iarpUpdatePending = true;
    if (IARP_updateTimer->isScheduled())
        cancelEvent(IARP_updateTimer);
    scheduleAfter(SimTime((int64_t)std::round(IARP_eventDelay + uniform(0, IARP_eventJitter)), SIMTIME_MS), IARP_updateTimer);
}

void Gzrp::handleIARPUpdate(const Ptr<IARP_LinkStateUpdate>& update, const L3Address& sourceAddr)
{
    L3Address originatorAddr = update->getSourceAddr();
    uint16_t seqNum = update->getSeqNum();

    EV_INFO << "Received IARP Link State Update from " << sourceAddr << " originated by " << originatorAddr
            << " (seq: " << seqNum << ", runningStability: " << (int)update->getRunningStability() << ")" << endl;

    if (originatorAddr == getSelfIPAddress()) {
        EV_DETAIL << "Ignoring own IARP update" << endl;
        return;
    }

    SelfState self = buildSelfState();
    double tau = self.threshold;
    uint8_t r_in = update->getRunningStability();

    // Admission and forwarder gates per the strategy plug-ins.
    if (!decayStrategy->isAdmissible(r_in, tau)) {
        DIAG_LOG(host, "IARP_RECV from=" << sourceAddr << " orig=" << originatorAddr
                                         << " seq=" << seqNum << " action=drop_admit");
        EV_DETAIL << "Dropping IARP update: decayStrategy->isAdmissible rejected (r_in=" << (int)r_in << ", tau=" << tau << ")" << endl;
        return;
    }

    if (!gateStrategy->nodePassesGate(self, tau)) {
        DIAG_LOG(host, "IARP_RECV from=" << sourceAddr << " orig=" << originatorAddr
                                         << " seq=" << seqNum << " action=drop_gate");
        EV_DETAIL << "Dropping IARP update: gate rejected (fringe receiver)" << endl;
        return;
    }

    auto it = linkStateTable.find(originatorAddr);
    if (it != linkStateTable.end()) {
        if (!seqNumIsNewer(seqNum, it->second.seqNum)) {
            DIAG_LOG(host, "IARP_RECV from=" << sourceAddr << " orig=" << originatorAddr
                                             << " seq=" << seqNum << " action=stale");
            EV_DETAIL << "Ignoring stale IARP update (have seq " << it->second.seqNum << ", received " << seqNum << ")"
                      << endl;
            return;
        }
    }

    LinkStateEntry entry;
    entry.sourceAddr = originatorAddr;
    entry.seqNum = seqNum;
    entry.insertTime = simTime();

    size_t destCount = update->getLinkDestCount();
    for (size_t i = 0; i < destCount; i++) {
        const auto& destData = update->getLinkDestData(i);
        LinkDestInfo info;
        info.destAddr = destData.addr;
        for (int m = 0; m < IARP_METRIC_COUNT; m++) {
            info.metrics[m] = destData.metrics[m].metricValue;
        }
        entry.linkDestinations.push_back(info);
    }

    linkStateTable[originatorAddr] = entry;
    DIAG_LOG(host, "IARP_RECV from=" << sourceAddr << " orig=" << originatorAddr
                                     << " seq=" << seqNum << " action=store nbrs=" << destCount);

    EV_DETAIL << "Updated link state table, now has " << linkStateTable.size() << " entries" << endl;

    IARP_updateRoutingTable();
    IERP_routeMaintenance();

    // Forwarder decay: produce the byte we would send next.
    uint8_t r_out = decayStrategy->decayState(r_in, self);

    if (!decayStrategy->shouldForward(r_out, tau)) {
        EV_DETAIL << "Admitted but not forwarding IARP update: decayStrategy->shouldForward rejected (r_out="
                  << (int)r_out << ", tau=" << tau << ")" << endl;
        return;
    }

    auto fwdUpdate = update->dupShared();
    auto mutableUpdate = CHK(dynamicPtrCast<IARP_LinkStateUpdate>(fwdUpdate));
    mutableUpdate->setRunningStability(r_out);

    EV_INFO << "Rebroadcasting IARP update with runningStability=" << (int)mutableUpdate->getRunningStability() << endl;
    sendZrpPacket(mutableUpdate, Ipv4Address::ALLONES_ADDRESS, 255);
}

void Gzrp::IARP_refreshLinkStateTable()
{
    EV_DETAIL << "Refreshing link state table..." << endl;

    simtime_t now = simTime();
    auto it = linkStateTable.begin();

    while (it != linkStateTable.end()) {
        if (now - it->second.insertTime > linkStateLifetime) {
            EV_INFO << "Removing stale link state entry for " << it->first << " (age: " << (now - it->second.insertTime)
                    << ")" << endl;
            it = linkStateTable.erase(it);
        }
        else {
            ++it;
        }
    }

    IARP_updateRoutingTable();
    IERP_routeMaintenance();
}

IRoute* Gzrp::IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                               const std::vector<L3Address>& fullRoute)
{
    IRoute* newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32);
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);
    newRoute->setSource(this);

    GzrpRouteData* routeData = new GzrpRouteData(GZRP_ROUTE_IARP);
    routeData->setSourceRoute(fullRoute);
    routeData->setDiscoveryTime(simTime());
    newRoute->setProtocolData(routeData);

    NetworkInterface* ifEntry = interfaceTable->findInterfaceByName(par("interface"));
    if (ifEntry) {
        newRoute->setInterface(ifEntry);
    }

    DIAG_LOG(host, "IARP_ROUTE_INSTALL dest=" << dest << " nextHop=" << nextHop << " hops=" << hops);
    EV_DETAIL << "Adding IARP route to " << dest << " via " << nextHop << " (hops: " << hops << ")" << endl;
    routingTable->addRoute(newRoute);

    return newRoute;
}

void Gzrp::IARP_purgeRoutingTable()
{
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (!routeData || routeData->isIarpRoute()) {
                EV_DETAIL << "Purging IARP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

void Gzrp::IARP_computeRoutes()
{
    // Strategy-driven Dijkstra. Admission and forwarder eligibility are
    // governed by the gate strategy; per-hop decay is governed by the decay
    // strategy. Self gets one pre-decay hop applied iff
    // enableOriginatorPreDecay is true; with pre-decay off, the first
    // relaxation out of self carries the running value through unchanged
    // (the unit-multiplier path documented in IStrategy.h).
    L3Address self = getSelfIPAddress();
    SelfState selfStateSelf = buildSelfState();
    double tau = selfStateSelf.threshold;
    bool selfPassesGate = gateStrategy->nodePassesGate(selfStateSelf, tau);

    struct DijkstraState {
        double value;
        unsigned int hops;
        L3Address prev;
    };

    std::map<L3Address, DijkstraState> state;
    std::set<L3Address> visited;

    // Max-heap priority. Primary key is path value (widest-path Dijkstra);
    // secondary key is -hops so that on a tie the SHORTEST-hop path pops
    // first. Without the hop tiebreak, GZRP-Classic (ConstantOneScore: every
    // path value = 1.0) falls through to L3Address ordering and installs
    // routes at non-minimum hop counts, diverging from classic ZRP.
    //
    // Address is the deterministic final tiebreak. Direction is set by the
    // decay strategy (IDecayStrategy::tiebreakPrefersLargerAddr):
    //   StepDecay -> false -> smallest-addr first -> matches ZRP's
    //     min-heap on (dist, addr).
    //   MultiplicativeBetaDecay -> true -> largest-addr first -> matches
    //     SAZRP's max-heap on (value, addr) with default less.
    // Same Dijkstra body, different tiebreak: keeps both parities.
    struct PQEntry {
        double value;
        int negHops;
        L3Address addr;
    };
    struct PQComp {
        bool preferLargerAddr;
        bool operator()(const PQEntry& a, const PQEntry& b) const {
            if (a.value != b.value) return a.value < b.value;
            if (a.negHops != b.negHops) return a.negHops < b.negHops;
            return preferLargerAddr ? (a.addr < b.addr) : (a.addr > b.addr);
        }
    };
    std::priority_queue<PQEntry, std::vector<PQEntry>, PQComp> pq(
        PQComp{decayStrategy->tiebreakPrefersLargerAddr()});

    state[self] = {1.0, 0, self};
    pq.push({1.0, 0, self});

    while (!pq.empty()) {
        auto top = pq.top();
        pq.pop();
        L3Address u = top.addr;

        if (visited.count(u))
            continue;
        visited.insert(u);

        EV_DETAIL << "IARP Dijkstra: visit " << u << " value=" << state[u].value
                  << " hops=" << state[u].hops << endl;

        // Build a SelfState representing u (for gate/decay calls "as if" u
        // were the local node). Held outside the if block so its temporary
        // neighbour map outlives the strategy calls below.
        std::map<L3Address, NeighbourState> tmpUNbrs;
        SelfState selfStateU = (u == self)
            ? selfStateSelf
            : buildSelfStateFor(u, tau, tmpUNbrs);

        bool isDirect1Hop = (u != self) && (neighbours.find(u) != neighbours.end());

        if (u != self) {
            bool admit;
            if (isDirect1Hop) {
                admit = true;
            }
            else if (!selfPassesGate) {
                admit = false;
            }
            else if (state[u].value < tau) {
                admit = false;
            }
            else if (!gateStrategy->nodePassesGate(selfStateU, tau)) {
                admit = false;
            }
            else {
                admit = true;
            }

            if (admit) {
                std::vector<L3Address> path;
                for (L3Address cur = u; cur != self; cur = state[cur].prev)
                    path.push_back(cur);
                path.push_back(self);
                std::reverse(path.begin(), path.end());

                L3Address nextHop = path.size() > 1 ? path[1] : u;
                IARP_createRoute(u, nextHop, state[u].hops, path);
            }
            else {
                continue;
            }
        }

        // Build u's neighbour list with per-link quality (for the
        // STABILITY_EPSILON guard only -- the relaxation itself uses the
        // decay strategy's value, not the per-link byte).
        std::vector<std::pair<L3Address, double>> nbrs;

        if (u == self) {
            for (const auto& entry : neighbours) {
                nbrs.push_back({entry.first, entry.second.quality});
            }
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations) {
                    double q = decodeStability(static_cast<uint8_t>(linkDest.metrics[0] & 0xFF));
                    nbrs.push_back({linkDest.destAddr, q});
                }
            }
        }

        // u is a forwarder iff its gate passes.
        bool uIsForwarder = (u == self) ? selfPassesGate
                                        : gateStrategy->nodePassesGate(selfStateU, tau);

        for (const auto& np : nbrs) {
            const L3Address& v = np.first;
            double q = np.second;
            if (visited.count(v))
                continue;

            bool isDirectFromSelf = (u == self) && (neighbours.find(v) != neighbours.end());

            // Drop links whose quality byte is effectively zero. Direct
            // 1-hop edges are exempt (the guarantee covers them no matter
            // how weak the link).
            if (q < STABILITY_EPSILON && !isDirectFromSelf)
                continue;

            // Only forwarders can extend the wave; 1-hop guarantee bypass.
            if (!uIsForwarder && !isDirectFromSelf)
                continue;

            // Relaxation. With pre-decay off, the first edge out of self
            // carries the running value through unchanged; on every other
            // edge (including all u != self), the decay strategy computes
            // the new value.
            double newValue;
            unsigned int newHops = state[u].hops + 1;
            if (u == self && !enableOriginatorPreDecay) {
                newValue = state[u].value;
            }
            else {
                newValue = decayStrategy->decayValueForDijkstra(state[u].value, newHops, selfStateU);
            }

            // Decay-imposed hop budget. Direct 1-hop edges are exempt.
            if (!isDirectFromSelf && newValue < tau)
                continue;

            auto sit = state.find(v);
            double currentValue = (sit == state.end()) ? 0.0 : sit->second.value;
            unsigned int currentHops = (sit == state.end())
                ? std::numeric_limits<unsigned int>::max()
                : sit->second.hops;
            // Improve on strictly higher value, OR same value with strictly
            // fewer hops. The hop tiebreak is what recovers shortest-hop
            // semantics in the constant-scoring case; with strict ">" alone,
            // an equally-good shorter path discovered after a longer one
            // would be silently dropped.
            if (newValue > currentValue ||
                (newValue == currentValue && newHops < currentHops)) {
                state[v] = {newValue, newHops, u};
                pq.push({newValue, -static_cast<int>(newHops), v});
            }
        }
    }
}

void Gzrp::IARP_updateRoutingTable()
{
    EV_INFO << "Updating IARP routing table..." << endl;

    IARP_purgeRoutingTable();

    IARP_computeRoutes();
}

// IERP

void Gzrp::IERP_initiateRouteDiscovery(const L3Address& dest, bool isRetry)
{
    EV_INFO << (isRetry ? "Retrying" : "Initiating")
            << " IERP route discovery for " << dest << endl;

    if (isRetry)
        emit(routeDiscoveryRetriedSignal, (intval_t)1);
    else {
        emit(routeDiscoveryStartedSignal, (intval_t)1);
        ierpDiscoveryStartTimes[dest] = simTime();
    }

    auto request = IERP_createRouteRequest(dest);

    IerpQueryId qid;
    qid.source = getSelfIPAddress();
    qid.queryId = request->getQueryID();
    IERP_recordQuery(qid, dest);

    DIAG_LOG(host, "IERP_INIT_RD dest=" << dest << " qid=" << qid.source << ":" << qid.queryId
                                        << " retry=" << (isRetry ? 1 : 0));

    BRP_bordercast(request);

    if (ierpRetryTimers.find(dest) == ierpRetryTimers.end()) {
        cMessage* retryMsg = new cMessage("IERP_retryTimer", GZRP_SELF_IERP_RETRY);
        retryMsg->addPar("destAddr") = (long)dest.toIpv4().getInt();
        ierpRetryTimers[dest] = retryMsg;
        scheduleAfter(ierpRetryInterval, retryMsg);
    }
}

const Ptr<IERP_RouteData> Gzrp::IERP_createRouteRequest(const L3Address& dest)
{
    auto request = makeShared<IERP_RouteData>();

    request->setType(IERP_QUERY);
    request->setNodePtr(0);
    request->setQueryID(IERP_queryId++);
    request->setSourceAddr(getSelfIPAddress());
    request->setDestAddr(dest);
    request->setIntermediateNodesArraySize(0);

    request->setLength(4);
    request->setChunkLength(B(16));

    EV_DETAIL << "Created IERP ROUTE_REQUEST: src=" << getSelfIPAddress() << ", dest=" << dest
              << ", queryID=" << request->getQueryID() << endl;

    return request;
}

const Ptr<IERP_RouteData> Gzrp::IERP_createRouteReply(const Ptr<IERP_RouteData>& request)
{
    auto reply = makeShared<IERP_RouteData>();

    reply->setType(IERP_REPLY);
    reply->setQueryID(request->getQueryID());
    reply->setSourceAddr(request->getSourceAddr());
    reply->setDestAddr(request->getDestAddr());

    size_t reqIntermediateCount = request->getIntermediateNodesArraySize();
    reply->setIntermediateNodesArraySize(reqIntermediateCount);
    for (size_t i = 0; i < reqIntermediateCount; i++) {
        reply->setIntermediateNodes(i, request->getIntermediateNodes(i));
    }

    reply->setNodePtr(reqIntermediateCount);

    size_t totalNodes = reqIntermediateCount;
    uint8_t lengthInWords = (16 + totalNodes * 4) / 4;
    reply->setLength(lengthInWords);
    reply->setChunkLength(B(16 + totalNodes * 4));

    EV_DETAIL << "Created IERP ROUTE_REPLY: src=" << reply->getSourceAddr() << ", dest=" << reply->getDestAddr()
              << ", queryID=" << reply->getQueryID() << ", route length=" << totalNodes << " intermediates" << endl;

    return reply;
}

void Gzrp::IERP_handleRouteRequest(const Ptr<IERP_RouteData>& request, const L3Address& sourceAddr)
{
    L3Address self = getSelfIPAddress();
    L3Address querySource = request->getSourceAddr();
    L3Address queryDest = request->getDestAddr();
    uint16_t queryID = request->getQueryID();

    EV_INFO << "IERP: Received ROUTE_REQUEST from " << sourceAddr << " (query src=" << querySource
            << ", dest=" << queryDest << ", queryID=" << queryID << ")" << endl;

    if (querySource == self) {
        EV_DETAIL << "IERP: Ignoring our own route request" << endl;
        return;
    }

    IerpQueryId qid;
    qid.source = querySource;
    qid.queryId = queryID;

    if (IERP_isQuerySeen(qid)) {
        EV_DETAIL << "IERP: Ignoring duplicate route request (already seen queryID=" << queryID << " from "
                  << querySource << ")" << endl;
        return;
    }

    for (size_t i = 0; i < request->getIntermediateNodesArraySize(); i++) {
        if (request->getIntermediateNodes(i) == self) {
            EV_DETAIL << "IERP: Loop detected, our address already in route" << endl;
            return;
        }
    }

    IERP_recordQuery(qid, queryDest);

    std::vector<L3Address> routeToSource;
    routeToSource.push_back(self);
    for (int i = (int)request->getIntermediateNodesArraySize() - 1; i >= 0; i--) {
        routeToSource.push_back(request->getIntermediateNodes(i));
    }
    routeToSource.push_back(querySource);

    if (!routingTable->findBestMatchingRoute(querySource) && !IERP_hasRouteToDestination(querySource)) {
        L3Address nextHop = routeToSource.size() > 1 ? routeToSource[1] : querySource;
        IERP_createRoute(querySource, nextHop, routeToSource.size() - 1, routeToSource);
    }

    IRoute* iarpRoute = nullptr;
    IRoute* ierpRoute = nullptr;

    if (queryDest != self) {
        for (int i = 0; i < routingTable->getNumRoutes(); i++) {
            IRoute* route = routingTable->getRoute(i);
            if (route->getSource() != this || route->getDestinationAsGeneric() != queryDest)
                continue;
            auto* rd = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (!rd || rd->isIarpRoute()) {
                iarpRoute = route;
                break;
            }
            if (rd->isIerpRoute() && !ierpRoute) {
                ierpRoute = route;
            }
        }
    }

    bool haveRoute = (queryDest == self) || iarpRoute || ierpRoute;

    if (haveRoute) {
        EV_INFO << "IERP: Found route to destination " << queryDest << ", sending ROUTE_REPLY" << endl;

        auto mutableRequest = request->dupShared();
        auto editableRequest = CHK(dynamicPtrCast<IERP_RouteData>(mutableRequest));

        size_t currentSize = editableRequest->getIntermediateNodesArraySize();
        editableRequest->setIntermediateNodesArraySize(currentSize + 1);
        editableRequest->setIntermediateNodes(currentSize, self);
        editableRequest->setNodePtr(currentSize + 1);

        IRoute* chosenRoute = iarpRoute ? iarpRoute : ierpRoute;
        if (queryDest != self && chosenRoute) {
            auto* rd = dynamic_cast<GzrpRouteData*>(chosenRoute->getProtocolData());
            if (rd) {
                const auto& srcRoute = rd->getSourceRoute();
                for (size_t i = 1; i + 1 < srcRoute.size(); i++) {
                    size_t sz = editableRequest->getIntermediateNodesArraySize();
                    editableRequest->setIntermediateNodesArraySize(sz + 1);
                    editableRequest->setIntermediateNodes(sz, srcRoute[i]);
                }
            }
        }

        auto reply = IERP_createRouteReply(editableRequest);

        L3Address nextHopToSource;
        if (editableRequest->getIntermediateNodesArraySize() >= 2) {
            nextHopToSource =
                editableRequest->getIntermediateNodes(editableRequest->getIntermediateNodesArraySize() - 2);
        }
        else {
            nextHopToSource = querySource;
        }

        sendZrpPacket(reply, nextHopToSource, 255);
    }
    else {
        EV_INFO << "IERP: No route to " << queryDest << ", forwarding ROUTE_REQUEST" << endl;

        auto mutableRequest = request->dupShared();
        auto editableRequest = CHK(dynamicPtrCast<IERP_RouteData>(mutableRequest));

        size_t currentSize = editableRequest->getIntermediateNodesArraySize();
        editableRequest->setIntermediateNodesArraySize(currentSize + 1);
        editableRequest->setIntermediateNodes(currentSize, self);
        editableRequest->setNodePtr(currentSize + 1);

        size_t totalNodes = editableRequest->getIntermediateNodesArraySize();
        uint8_t lengthInWords = (16 + totalNodes * 4) / 4;
        editableRequest->setLength(lengthInWords);
        editableRequest->setChunkLength(B(16 + totalNodes * 4));

        BRP_bordercast(editableRequest);
    }
}

void Gzrp::IERP_handleRouteReply(const Ptr<IERP_RouteData>& reply, const L3Address& sourceAddr)
{
    L3Address self = getSelfIPAddress();
    L3Address routeSource = reply->getSourceAddr();
    L3Address routeDest = reply->getDestAddr();
    uint16_t queryID = reply->getQueryID();

    EV_INFO << "IERP: Received ROUTE_REPLY from " << sourceAddr << " (route src=" << routeSource
            << ", dest=" << routeDest << ", queryID=" << queryID << ")" << endl;

    std::vector<L3Address> fullRoute;
    fullRoute.push_back(routeSource);
    for (size_t i = 0; i < reply->getIntermediateNodesArraySize(); i++) {
        fullRoute.push_back(reply->getIntermediateNodes(i));
    }
    fullRoute.push_back(routeDest);

    int myPos = -1;
    for (size_t i = 0; i < fullRoute.size(); i++) {
        if (fullRoute[i] == self) {
            myPos = (int)i;
            break;
        }
    }

    if (myPos < 0) {
        EV_WARN << "IERP: We are not in the route of this ROUTE_REPLY, discarding" << endl;
        return;
    }

    std::vector<L3Address> routeToDest;
    for (size_t i = myPos; i < fullRoute.size(); i++) {
        routeToDest.push_back(fullRoute[i]);
    }

    // Arbitration between competing replies. Two policies:
    //   "last-wins" (classic ZRP):  every reply replaces the installed route.
    //   "stability-hops" (SAZRP):   high-quality next hop wins, else fewer
    //                                hops, else keep existing (first-come).
    // The policy is selected by ierpReplyInstallLastWins (driven by the
    // ierpReplyInstallPolicy NED parameter). GZRP-Classic configs must set
    // "last-wins" to match ZRP exactly; without it, two replies for the
    // same destination via the same hop count would have the first one stick
    // even when a fresher reply carries an equally-good but newer route.
    if (routeToDest.size() > 1) {
        L3Address nextHop = routeToDest[1];
        unsigned int hops = routeToDest.size() - 1;

        IRoute* existingRoute = IERP_findRoute(routeDest);
        bool shouldInstall = true;

        if (ierpReplyInstallLastWins) {
            shouldInstall = true; // ZRP semantics: always replace
        }
        else if (existingRoute) {
            SelfState selfState = buildSelfState();
            double tau = selfState.threshold;

            auto isLowStabNextHop = [&](const L3Address& nh) {
                auto sIt = neighbours.find(nh);
                return (sIt != neighbours.end()) && (sIt->second.quality < tau);
            };

            L3Address oldNextHop = existingRoute->getNextHopAsGeneric();
            unsigned int oldHops = existingRoute->getMetric();
            bool newLow = isLowStabNextHop(nextHop);
            bool oldLow = isLowStabNextHop(oldNextHop);
            if (newLow != oldLow) {
                shouldInstall = !newLow;
            }
            else {
                shouldInstall = (hops < oldHops);
            }
        }

        if (shouldInstall) {
            if (existingRoute)
                routingTable->deleteRoute(existingRoute);
            IERP_createRoute(routeDest, nextHop, hops, routeToDest);

            EV_INFO << "IERP: Installed route to " << routeDest << " via " << nextHop << " (" << hops
                    << " hops, full route: ";
            for (size_t i = 0; i < routeToDest.size(); i++) {
                if (i > 0)
                    EV_INFO << "->";
                EV_INFO << routeToDest[i];
            }
            EV_INFO << ")" << endl;
        }
        else {
            EV_INFO << "IERP: Keeping existing route to " << routeDest << " (existing via "
                    << existingRoute->getNextHopAsGeneric() << ", " << existingRoute->getMetric()
                    << " hops; new via " << nextHop << ", " << hops
                    << " hops -- existing wins on stability/hop/first-come tiebreak)" << endl;
        }
    }

    if (self != routeSource) {
        auto fwdReply = reply->dupShared();
        auto editableReply = CHK(dynamicPtrCast<IERP_RouteData>(fwdReply));

        uint8_t nodePtr = editableReply->getNodePtr();
        if (nodePtr > 0) {
            nodePtr--;
            editableReply->setNodePtr(nodePtr);
        }

        L3Address nextHopToSource;
        if (myPos > 1) {
            nextHopToSource = fullRoute[myPos - 1];
        }
        else {
            nextHopToSource = routeSource;
        }

        EV_INFO << "IERP: Forwarding ROUTE_REPLY toward source via " << nextHopToSource << endl;

        sendZrpPacket(editableReply, nextHopToSource, 255);
    }
    else {
        EV_INFO << "IERP: ROUTE_REPLY reached query source. Route discovery complete for " << routeDest << endl;
        IERP_completeRouteDiscovery(routeDest);
    }
}

void Gzrp::IERP_routeMaintenance()
{
    L3Address self = getSelfIPAddress();

    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() != this)
            continue;

        auto* routeData = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
        if (!routeData || !routeData->isIerpRoute())
            continue;

        const std::vector<L3Address>& sourceRoute = routeData->getSourceRoute();
        if (sourceRoute.size() < 2)
            continue;

        L3Address dest = route->getDestinationAsGeneric();

        unsigned int minDist = sourceRoute.size() - 1;
        std::vector<L3Address> bestRoute = sourceRoute;
        bool improved = false;

        for (size_t j = 1; j < sourceRoute.size(); j++) {
            L3Address intermediateNode = sourceRoute[j];

            IRoute* iarpRoute = nullptr;
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute* candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this && candidate->getDestinationAsGeneric() == intermediateNode) {
                    auto* candData = dynamic_cast<GzrpRouteData*>(candidate->getProtocolData());
                    if (candData && candData->isIarpRoute()) {
                        iarpRoute = candidate;
                        break;
                    }
                }
            }

            if (iarpRoute) {
                unsigned int iarpHops = iarpRoute->getMetric();
                unsigned int tailHops = sourceRoute.size() - 1 - j;
                unsigned int totalHops = iarpHops + tailHops;

                if (totalHops < minDist) {
                    minDist = totalHops;

                    bestRoute.clear();
                    bestRoute.push_back(self);
                    for (size_t k = j; k < sourceRoute.size(); k++) {
                        bestRoute.push_back(sourceRoute[k]);
                    }

                    improved = true;
                }
            }
        }

        if (improved) {
            EV_INFO << "IERP: Route maintenance shortened route to " << dest << " from " << (sourceRoute.size() - 1)
                    << " to " << minDist << " hops" << endl;

            route->setNextHop(bestRoute.size() > 1 ? bestRoute[1] : dest);
            route->setMetric(minDist);
            routeData->setSourceRoute(bestRoute);
        }

        L3Address nextHop = route->getNextHopAsGeneric();
        bool nextHopReachable = false;

        if (neighbours.find(nextHop) != neighbours.end()) {
            nextHopReachable = true;
        }
        else {
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute* candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this && candidate->getDestinationAsGeneric() == nextHop) {
                    auto* candData = dynamic_cast<GzrpRouteData*>(candidate->getProtocolData());
                    if (candData && candData->isIarpRoute()) {
                        nextHopReachable = true;
                        break;
                    }
                }
            }
        }

        if (!nextHopReachable) {
            EV_WARN << "IERP: Next hop " << nextHop << " for route to " << dest
                    << " is no longer reachable. Removing broken route." << endl;
            routingTable->deleteRoute(route);
        }
    }
}

IRoute* Gzrp::IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                               const std::vector<L3Address>& fullRoute)
{
    IRoute* newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32);
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);
    newRoute->setSource(this);

    GzrpRouteData* routeData = new GzrpRouteData(GZRP_ROUTE_IERP);
    routeData->setSourceRoute(fullRoute);
    routeData->setDiscoveryTime(simTime());
    newRoute->setProtocolData(routeData);

    NetworkInterface* ifEntry = interfaceTable->findInterfaceByName(par("interface"));
    if (ifEntry) {
        newRoute->setInterface(ifEntry);
    }

    DIAG_LOG(host, "IERP_ROUTE_INSTALL dest=" << dest << " nextHop=" << nextHop << " hops=" << hops);
    EV_DETAIL << "Adding IERP route to " << dest << " via " << nextHop << " (" << hops << " hops)" << endl;
    routingTable->addRoute(newRoute);

    return newRoute;
}

void Gzrp::IERP_purgeRoutingTable()
{
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                EV_DETAIL << "Purging IERP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

bool Gzrp::IERP_hasRouteToDestination(const L3Address& dest) const
{
    return IERP_findRoute(dest) != nullptr;
}

IRoute* Gzrp::IERP_findRoute(const L3Address& dest) const
{
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == dest) {
            auto* routeData = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                return route;
            }
        }
    }
    return nullptr;
}

bool Gzrp::IERP_hasOngoingDiscovery(const L3Address& dest) const
{
    L3Address self = getSelfIPAddress();
    for (const auto& entry : ierpQueryTable) {
        if (entry.first.source == self && entry.second.destination == dest && !entry.second.replied) {
            return true;
        }
    }
    return false;
}

void Gzrp::IERP_delayDatagram(Packet* datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& dest = networkHeader->getDestinationAddress();
    EV_DETAIL << "Buffering datagram for destination " << dest << endl;
    delayedPackets.insert({dest, {simTime(), datagram}});
}

void Gzrp::IERP_completeRouteDiscovery(const L3Address& dest)
{
    EV_DETAIL << "Completing route discovery for " << dest << ", releasing " << delayedPackets.count(dest)
              << " buffered datagrams" << endl;

    auto stIt = ierpDiscoveryStartTimes.find(dest);
    if (stIt != ierpDiscoveryStartTimes.end()) {
        simtime_t elapsed = simTime() - stIt->second;
        emit(routeDiscoveryTimeSignal, elapsed.dbl());
        IRoute* installed = IERP_findRoute(dest);
        if (installed)
            emit(routeLengthSignal, (intval_t)installed->getMetric());
        ierpDiscoveryStartTimes.erase(stIt);
    }

    auto lt = delayedPackets.lower_bound(dest);
    auto ut = delayedPackets.upper_bound(dest);

    simtime_t now = simTime();
    for (auto it = lt; it != ut; it++) {
        Packet* datagram = it->second.second;
        simtime_t age = now - it->second.first;
        const auto& networkHeader = getNetworkProtocolHeader(datagram);
        if (age > delayedPacketLifetime) {
            EV_WARN << "Dropping stale buffered datagram (age " << age << "s > "
                    << delayedPacketLifetime << "s): src=" << networkHeader->getSourceAddress()
                    << ", dest=" << networkHeader->getDestinationAddress() << endl;
            networkProtocol->dropQueuedDatagram(datagram);
        }
        else {
            EV_DETAIL << "Reinjecting buffered datagram: src=" << networkHeader->getSourceAddress()
                      << ", dest=" << networkHeader->getDestinationAddress() << endl;
            networkProtocol->reinjectQueuedDatagram(datagram);
        }
    }

    delayedPackets.erase(lt, ut);

    L3Address self = getSelfIPAddress();
    for (auto& entry : ierpQueryTable) {
        if (entry.first.source == self && entry.second.destination == dest) {
            entry.second.replied = true;
        }
    }

    auto retryIt = ierpRetryTimers.find(dest);
    if (retryIt != ierpRetryTimers.end()) {
        cancelAndDelete(retryIt->second);
        ierpRetryTimers.erase(retryIt);
    }
    ierpRetryCounters.erase(dest);
}

bool Gzrp::IERP_isQuerySeen(const IerpQueryId& qid) const
{
    return ierpQueryTable.find(qid) != ierpQueryTable.end();
}

void Gzrp::IERP_recordQuery(const IerpQueryId& qid, const L3Address& dest)
{
    IerpQueryRecord record;
    record.queryId = qid;
    record.destination = dest;
    record.receiveTime = simTime();
    record.replied = false;
    ierpQueryTable[qid] = record;
}

void Gzrp::IERP_cleanQueryTable()
{
    simtime_t now = simTime();
    simtime_t queryLifetime = 120;

    auto it = ierpQueryTable.begin();
    while (it != ierpQueryTable.end()) {
        if (now - it->second.receiveTime > queryLifetime) {
            it = ierpQueryTable.erase(it);
        }
        else {
            ++it;
        }
    }
}

// BRP

void Gzrp::BRP_bordercast(const Ptr<IERP_RouteData>& packet)
{
    L3Address self = getSelfIPAddress();
    L3Address queryDest = packet->getDestAddr();

    IerpQueryId qid;
    qid.source = packet->getSourceAddr();
    qid.queryId = packet->getQueryID();

    int cacheId = BRP_findOrCreateCoverage(qid);

    auto& coverage = brpCoverageTable[cacheId];

    std::set<L3Address> outNeighbours;

    bool haveIarpRouteToDest = false;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == queryDest) {
            auto* rd = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (rd && rd->isIarpRoute()) {
                haveIarpRouteToDest = true;
                if (coverage.coveredNodes.find(queryDest) == coverage.coveredNodes.end()) {
                    outNeighbours.insert(route->getNextHopAsGeneric());
                }
                break;
            }
        }
    }

    if (!haveIarpRouteToDest) {
        std::set<L3Address> peripherals = BRP_getMyPeripherals();

        std::set<L3Address> uncoveredPeripherals;
        for (const auto& p : peripherals) {
            if (coverage.coveredNodes.find(p) == coverage.coveredNodes.end()) {
                uncoveredPeripherals.insert(p);
            }
        }

        EV_DETAIL << "BRP: Peripheral nodes: " << peripherals.size() << ", uncovered: " << uncoveredPeripherals.size()
                  << endl;

        if (!uncoveredPeripherals.empty()) {
            outNeighbours = BRP_getOutNeighbours(uncoveredPeripherals);
        }
    }

    if (outNeighbours.empty()) {
        DIAG_LOG(host, "BRP_BORDERCAST qid=" << qid.source << ":" << qid.queryId
                                             << " dest=" << queryDest << " out=0");
        EV_INFO << "BRP: No uncovered peripheral nodes to bordercast to" << endl;
    }
    else {
        printDebugTables();
        EV_INFO << "BRP: Bordercasting to " << outNeighbours.size() << " neighbour(s): ";
        for (const auto& n : outNeighbours)
            EV_INFO << n << " ";
        EV_INFO << endl;

        {
            std::ostringstream onbrs;
            for (const auto& n : outNeighbours) onbrs << n << ",";
            DIAG_LOG(host, "BRP_BORDERCAST qid=" << qid.source << ":" << qid.queryId
                                                 << " dest=" << queryDest
                                                 << " out=" << outNeighbours.size()
                                                 << " neighbours=[" << onbrs.str() << "]");
        }

        for (const auto& neighbour : outNeighbours) {
            auto brpPacket = makeShared<BRP_Data>();
            brpPacket->setSourceAddr(qid.source);
            brpPacket->setDestAddr(queryDest);
            brpPacket->setQueryID(qid.queryId);
            brpPacket->setQueryExtension(0);
            brpPacket->setPrevBordercastAddr(self);

            IERP_RouteData encapCopy;
            encapCopy.setType(packet->getType());
            encapCopy.setLength(packet->getLength());
            encapCopy.setNodePtr(packet->getNodePtr());
            encapCopy.setQueryID(packet->getQueryID());
            encapCopy.setSourceAddr(packet->getSourceAddr());
            encapCopy.setDestAddr(packet->getDestAddr());
            encapCopy.setIntermediateNodesArraySize(packet->getIntermediateNodesArraySize());
            for (size_t i = 0; i < packet->getIntermediateNodesArraySize(); i++)
                encapCopy.setIntermediateNodes(i, packet->getIntermediateNodes(i));
            brpPacket->setEncapsulatedPacket(encapCopy);

            brpPacket->setChunkLength(B(16) + packet->getChunkLength());

            sendZrpPacket(brpPacket, neighbour, 255);
        }
    }

    std::set<L3Address> myZone = BRP_getMyZone();
    BRP_recordCoverage(cacheId, myZone);
}

void Gzrp::BRP_deliver(const Ptr<BRP_Data>& brpPacket, const L3Address& sourceAddr)
{
    L3Address self = getSelfIPAddress();
    L3Address prevBordercaster = brpPacket->getPrevBordercastAddr();
    L3Address querySource = brpPacket->getSourceAddr();
    L3Address queryDest = brpPacket->getDestAddr();
    uint16_t queryID = brpPacket->getQueryID();

    EV_INFO << "BRP: Received BRP packet from " << sourceAddr << " (prevBcast=" << prevBordercaster
            << ", query src=" << querySource << ", dest=" << queryDest << ", queryID=" << queryID << ")" << endl;

    IerpQueryId qid;
    qid.source = querySource;
    qid.queryId = queryID;

    int cacheId = BRP_findOrCreateCoverage(qid);

    std::set<L3Address> prevBcastZone;
    bool isOutNbr = BRP_isOutNeighbour(prevBordercaster, self, brpCoverageTable[cacheId].coveredNodes, prevBcastZone);
    BRP_recordCoverage(cacheId, prevBcastZone);
    DIAG_LOG(host, "BRP_RECV from=" << sourceAddr << " prev=" << prevBordercaster
                                    << " qid=" << querySource << ":" << queryID
                                    << " isOutNbr=" << (isOutNbr ? 1 : 0)
                                    << " delivered=" << (brpCoverageTable[cacheId].delivered ? 1 : 0));

    if (isOutNbr && !brpCoverageTable[cacheId].delivered) {
        brpCoverageTable[cacheId].delivered = true;
        simtime_t jitter = uniform(0, brpJitterMax);

        EV_DETAIL << "BRP: We are an out_neighbour of " << prevBordercaster
                  << ", scheduling IERP delivery with jitter=" << jitter << "s" << endl;

        cMessage* jitterMsg = new cMessage("BRP_jitter", GZRP_SELF_BRP_JITTER);
        jitterMsg->addPar("brpCacheId") = cacheId;

        auto* brpCopy = new BRP_Data();
        brpCopy->setSourceAddr(querySource);
        brpCopy->setDestAddr(queryDest);
        brpCopy->setQueryID(queryID);
        brpCopy->setQueryExtension(brpPacket->getQueryExtension());
        brpCopy->setPrevBordercastAddr(prevBordercaster);
        brpCopy->setEncapsulatedPacket(brpPacket->getEncapsulatedPacket());
        jitterMsg->setContextPointer(brpCopy);

        schedulePendingTimer(jitterMsg, jitter);
    }
    else {
        if (isOutNbr) {
            EV_DETAIL << "BRP: Already scheduled delivery for this query (cacheId=" << cacheId
                      << "), updating coverage only" << endl;
        }
        else {
            EV_DETAIL << "BRP: Not an out_neighbour of " << prevBordercaster
                      << ", marking own zone as covered and discarding" << endl;
        }

        std::set<L3Address> myZone = BRP_getMyZone();
        BRP_recordCoverage(cacheId, myZone);
    }
}

std::set<L3Address> Gzrp::BRP_getMyZone() const
{
    std::set<L3Address> zone;
    zone.insert(getSelfIPAddress());

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* rd = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (rd && rd->isIarpRoute()) {
                zone.insert(route->getDestinationAsGeneric());
            }
        }
    }

    return zone;
}

std::set<L3Address> Gzrp::BRP_getMyPeripherals() const
{
    std::set<L3Address> peripherals;
    L3Address self = getSelfIPAddress();

    // Two peripheral derivations, matched to the decay strategy's semantic
    // (mirrors BRP_isOutNeighbour's prev-rooted peripheral logic):
    //
    //   Hop-bounded decay (StepDecay / classic ZRP):
    //     v is peripheral iff the decay strategy would prune its outgoing
    //     relaxation -- i.e. decayValueForDijkstra(v.value, v.hops+1) < tau.
    //     For StepDecay with all-1.0 path values this collapses to
    //     "route.metric == decay.radius", the exact ZRP rule. Iterating IARP
    //     routes self-rooted gives us v.hops directly (route->getMetric()),
    //     no Dijkstra wave needed. ZRP parity holds for every R, including
    //     R=1 (where peripherals are the 1-hop neighbours themselves).
    //
    //   Value-bounded decay (MultiplicativeBetaDecay / SAZRP):
    //     v is peripheral iff at least one of v's reported neighbours is
    //     outside our zone. The grenade overshoots the zone here so every
    //     zone member has linkstate and this topological check works.
    if (decayStrategy->peripheralByHopBudget()) {
        SelfState selfState = const_cast<Gzrp*>(this)->buildSelfState();
        double tau = selfState.threshold;
        for (int i = 0; i < routingTable->getNumRoutes(); i++) {
            IRoute* route = routingTable->getRoute(i);
            if (route->getSource() != this) continue;
            auto* rd = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
            if (!rd || !rd->isIarpRoute()) continue;
            L3Address dest = route->getDestinationAsGeneric();
            if (dest == self) continue;
            unsigned int hops = route->getMetric();
            // value at v is 1.0 under any hop-bounded scoring/decay where
            // every admitted edge contributes a unit multiplier (i.e. the
            // only decay we currently classify as hop-bounded, StepDecay).
            double hypotheticalNext = decayStrategy->decayValueForDijkstra(
                1.0, hops + 1, selfState);
            if (hypotheticalNext < tau)
                peripherals.insert(dest);
        }
    }
    else {
        std::set<L3Address> zone = BRP_getMyZone();
        for (const auto& v : zone) {
            if (v == self) continue;
            std::set<L3Address> vNbrs;
            bool haveLinkState = false;
            auto lsIt = linkStateTable.find(v);
            if (lsIt != linkStateTable.end()) {
                for (const auto& ld : lsIt->second.linkDestinations) {
                    vNbrs.insert(ld.destAddr);
                }
                haveLinkState = true;
            }
            bool isDirect1Hop = (neighbours.find(v) != neighbours.end());
            if (isDirect1Hop) {
                vNbrs.insert(self);
            }
            // Fringe-self bordercast continuity (kept verbatim from SAZRP):
            // when self is fringe and hasn't accepted any IARP grenades, our
            // zone collapses to the 1-hop guarantee set and no zone member
            // has linkstate. Without intervention the bordercast dies on the
            // floor. SAZRP recovers by treating direct 1-hop neighbours as
            // peripherals in that case. This is SAZRP-only -- the hop-bounded
            // branch above is ZRP-equivalent and ZRP does not have this
            // accommodation.
            if (isDirect1Hop && !haveLinkState) {
                peripherals.insert(v);
                continue;
            }
            for (const auto& n : vNbrs) {
                if (zone.find(n) == zone.end()) {
                    peripherals.insert(v);
                    break;
                }
            }
        }
    }

    return peripherals;
}

std::set<L3Address> Gzrp::BRP_getOutNeighbours(const std::set<L3Address>& uncoveredPeripherals) const
{
    std::set<L3Address> outNeighbours;

    for (const auto& peripheral : uncoveredPeripherals) {
        for (int i = 0; i < routingTable->getNumRoutes(); i++) {
            IRoute* route = routingTable->getRoute(i);
            if (route->getSource() == this && route->getDestinationAsGeneric() == peripheral) {
                auto* rd = dynamic_cast<GzrpRouteData*>(route->getProtocolData());
                if (rd && rd->isIarpRoute()) {
                    outNeighbours.insert(route->getNextHopAsGeneric());
                    break;
                }
            }
        }
    }

    return outNeighbours;
}

bool Gzrp::BRP_isOutNeighbour(const L3Address& prevBordercaster, const L3Address& node,
                             const std::set<L3Address>& coveredNodes, std::set<L3Address>& outPrevZone) const
{
    // Parallel of IARP_computeRoutes, but rooted at prevBordercaster instead
    // of self. The strategy calls are identical; the only structural change
    // is that "self" in the gate/decay calls is prevBordercaster's SelfState.
    //
    // Hops are tracked alongside value so the decay strategy can apply a
    // hop-bounded budget (essential for StepDecay -- without it the wave
    // walks the entire reachable graph and outPrevZone over-covers the
    // BRP coverage table, starving downstream bordercasts of peripherals).
    struct SState {
        double value;
        unsigned int hops;
        L3Address nextHop;
    };
    std::map<L3Address, SState> state;
    std::set<L3Address> visited;

    // Max-heap on (value, -hops, addr). Address tiebreak direction is set
    // by the decay strategy (mirrors IARP_computeRoutes):
    //   StepDecay -> smallest-addr first (ZRP parity).
    //   MultiplicativeBetaDecay -> largest-addr first (SAZRP parity).
    // Keeping the bordercast Dijkstra consistent with the IARP Dijkstra is
    // important: the bordercast tree's next-hop pick on equal-cost paths
    // must agree with the routing table's next-hop pick, otherwise the
    // bordercast targets and the data forwarders disagree.
    struct PQEntry {
        double value;
        int negHops;
        L3Address addr;
    };
    struct PQComp {
        bool preferLargerAddr;
        bool operator()(const PQEntry& a, const PQEntry& b) const {
            if (a.value != b.value) return a.value < b.value;
            if (a.negHops != b.negHops) return a.negHops < b.negHops;
            return preferLargerAddr ? (a.addr < b.addr) : (a.addr > b.addr);
        }
    };
    std::priority_queue<PQEntry, std::vector<PQEntry>, PQComp> pq(
        PQComp{decayStrategy->tiebreakPrefersLargerAddr()});

    state[prevBordercaster] = {1.0, 0, prevBordercaster};
    pq.push({1.0, 0, prevBordercaster});

    L3Address self = getSelfIPAddress();
    SelfState selfStateSelf = const_cast<Gzrp*>(this)->buildSelfState();
    double tau = selfStateSelf.threshold;

    // Build a SelfState for prevBordercaster. Held here so its temporary
    // neighbour map outlives the Dijkstra body.
    std::map<L3Address, NeighbourState> tmpPrevNbrs;
    SelfState selfStatePrev = (prevBordercaster == self)
        ? selfStateSelf
        : const_cast<Gzrp*>(this)->buildSelfStateFor(prevBordercaster, tau, tmpPrevNbrs);

    std::set<L3Address> prevOneHop;
    if (prevBordercaster == self) {
        for (const auto& entry : neighbours) prevOneHop.insert(entry.first);
    }
    else {
        auto it0 = linkStateTable.find(prevBordercaster);
        if (it0 != linkStateTable.end()) {
            for (const auto& ld : it0->second.linkDestinations) prevOneHop.insert(ld.destAddr);
        }
        if (neighbours.find(prevBordercaster) != neighbours.end()) {
            prevOneHop.insert(self);
        }
    }

    bool prevPassesGate = gateStrategy->nodePassesGate(selfStatePrev, tau);

    while (!pq.empty()) {
        auto top = pq.top();
        pq.pop();
        L3Address u = top.addr;

        if (visited.count(u))
            continue;
        visited.insert(u);

        // SelfState for u in this Dijkstra. Self and prevBordercaster reuse
        // the cached states.
        std::map<L3Address, NeighbourState> tmpUNbrs;
        SelfState selfStateU;
        if (u == prevBordercaster) {
            selfStateU = selfStatePrev;
        }
        else if (u == self) {
            selfStateU = selfStateSelf;
        }
        else {
            selfStateU = const_cast<Gzrp*>(this)->buildSelfStateFor(u, tau, tmpUNbrs);
        }

        bool isDirect1Hop = (u != prevBordercaster) && (prevOneHop.find(u) != prevOneHop.end());
        bool admit;
        if (u == prevBordercaster) {
            admit = true;
        }
        else if (isDirect1Hop) {
            admit = true;
        }
        else if (!prevPassesGate) {
            admit = false;
        }
        else if (state[u].value < tau) {
            admit = false;
        }
        else if (!gateStrategy->nodePassesGate(selfStateU, tau)) {
            admit = false;
        }
        else {
            admit = true;
        }

        if (!admit)
            continue;

        outPrevZone.insert(u);

        std::vector<std::pair<L3Address, double>> nbrs;
        if (u == self) {
            for (const auto& entry : neighbours) {
                nbrs.push_back({entry.first, entry.second.quality});
            }
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations) {
                    double q = decodeStability(static_cast<uint8_t>(linkDest.metrics[0] & 0xFF));
                    nbrs.push_back({linkDest.destAddr, q});
                }
            }
            // u may be our direct NDP neighbour without an outgoing link
            // state entry naming us. Make sure the self edge is exposed so
            // the bordercast tree is symmetric.
            if (neighbours.find(u) != neighbours.end()) {
                bool selfAlreadyListed = false;
                for (const auto& n : nbrs) {
                    if (n.first == self) {
                        selfAlreadyListed = true;
                        break;
                    }
                }
                if (!selfAlreadyListed) {
                    double q = 0.0;
                    auto sIt = neighbours.find(u);
                    if (sIt != neighbours.end()) q = sIt->second.quality;
                    nbrs.push_back({self, q});
                }
            }
        }

        bool uIsForwarder = (u == prevBordercaster) ? prevPassesGate
                                                    : gateStrategy->nodePassesGate(selfStateU, tau);

        for (const auto& np : nbrs) {
            const L3Address& v = np.first;
            double q = np.second;
            if (visited.count(v))
                continue;

            bool isDirectFromPrev = (u == prevBordercaster) && (prevOneHop.find(v) != prevOneHop.end());

            if (q < STABILITY_EPSILON && !isDirectFromPrev)
                continue;

            if (!uIsForwarder && !isDirectFromPrev)
                continue;

            // Relaxation. pre-decay off at the origin (u==prevBordercaster)
            // passes the value through unchanged. newHops is the real hop
            // count from prevBordercaster -- StepDecay needs it to enforce
            // the radius gate, otherwise the wave never terminates by decay
            // and outPrevZone over-covers far past the true zone boundary.
            unsigned int newHops = state[u].hops + 1;
            double newValue;
            if (u == prevBordercaster && !enableOriginatorPreDecay) {
                newValue = state[u].value;
            }
            else {
                newValue = decayStrategy->decayValueForDijkstra(state[u].value, newHops, selfStateU);
            }

            if (!isDirectFromPrev && newValue < tau)
                continue;

            auto sit = state.find(v);
            double currentValue = (sit == state.end()) ? 0.0 : sit->second.value;
            unsigned int currentHops = (sit == state.end())
                ? std::numeric_limits<unsigned int>::max()
                : sit->second.hops;
            // Improve on strictly higher value, OR same value with strictly
            // fewer hops. Matches the IARP_computeRoutes tiebreak so the
            // bordercast Dijkstra picks shortest-hop paths under constant
            // scoring (without this, ConstantOneScore + ties devolves to
            // L3Address order and the next-hop pick diverges from ZRP).
            if (newValue > currentValue ||
                (newValue == currentValue && newHops < currentHops)) {
                L3Address nh = (u == prevBordercaster) ? v : state[u].nextHop;
                state[v] = {newValue, newHops, nh};
                pq.push({newValue, -static_cast<int>(newHops), v});
            }
        }
    }

    // Derive peripherals. Two semantics, chosen by the decay strategy:
    //
    //   Hop-budget (StepDecay / classic ZRP):
    //     v is peripheral iff its outgoing relaxation would be pruned by
    //     decay. Strategy-neutral expression of "metric == zoneRadius".
    //     Rooted purely on the Dijkstra wave we just computed -- our local
    //     linkStateTable is the WRONG reference frame here (its boundary
    //     is at R-1 hops from us, not from prevBordercaster), so the
    //     linkstate-based check used self-rooted would mis-mark nodes.
    //
    //   Topological (MultiplicativeBetaDecay / SAZRP):
    //     v is peripheral iff at least one of v's neighbours is outside
    //     outPrevZone (per our linkStateTable view). This is the SAZRP
    //     definition and is preserved verbatim so GZRP-Sazrp continues to
    //     match StabilityZrp exactly. SAZRP's grenade overshoots its zone,
    //     so the linkstate proxy works rooted-at-prev as well as
    //     rooted-at-self for the simulated topologies.
    std::set<L3Address> peripherals;
    if (decayStrategy->peripheralByHopBudget()) {
        for (const auto& kv : state) {
            const L3Address& v = kv.first;
            const SState& sv = kv.second;
            if (v == prevBordercaster)
                continue;
            if (outPrevZone.find(v) == outPrevZone.end())
                continue;

            SelfState selfStateV;
            std::map<L3Address, NeighbourState> tmpVNbrs;
            if (v == self) {
                selfStateV = selfStateSelf;
            }
            else {
                selfStateV = const_cast<Gzrp*>(this)->buildSelfStateFor(v, tau, tmpVNbrs);
            }

            double hypotheticalNext = decayStrategy->decayValueForDijkstra(
                sv.value, sv.hops + 1, selfStateV);
            if (hypotheticalNext < tau) {
                peripherals.insert(v);
            }
        }
    }
    else {
        for (const auto& v : outPrevZone) {
            if (v == prevBordercaster)
                continue;

            std::set<L3Address> vNbrs;
            auto lsIt = linkStateTable.find(v);
            if (lsIt != linkStateTable.end()) {
                for (const auto& ld : lsIt->second.linkDestinations) vNbrs.insert(ld.destAddr);
            }
            if (neighbours.find(v) != neighbours.end()) {
                vNbrs.insert(self);
            }

            for (const auto& n : vNbrs) {
                if (outPrevZone.find(n) == outPrevZone.end()) {
                    peripherals.insert(v);
                    break;
                }
            }
        }
    }

    for (const auto& peripheral : peripherals) {
        if (coveredNodes.find(peripheral) == coveredNodes.end()) {
            auto sit = state.find(peripheral);
            if (sit != state.end() && sit->second.nextHop == node) {
                return true;
            }
        }
    }

    return false;
}

void Gzrp::BRP_recordCoverage(int brpCacheId, const std::set<L3Address>& nodes)
{
    auto it = brpCoverageTable.find(brpCacheId);
    if (it != brpCoverageTable.end()) {
        it->second.coveredNodes.insert(nodes.begin(), nodes.end());
    }
}

int Gzrp::BRP_findOrCreateCoverage(const IerpQueryId& qid)
{
    for (auto& entry : brpCoverageTable) {
        if (entry.second.queryId == qid) {
            return entry.first;
        }
    }

    int newCacheId = BRP_bordercastId++;
    BrpQueryCoverage cov;
    cov.queryId = qid;
    cov.brpCacheId = newCacheId;
    cov.createTime = simTime();
    cov.delivered = false;
    brpCoverageTable[newCacheId] = cov;

    EV_DETAIL << "BRP: Created coverage entry " << newCacheId << " for query (src=" << qid.source
              << ", id=" << qid.queryId << ")" << endl;

    return newCacheId;
}

void Gzrp::BRP_cleanCoverageTable()
{
    simtime_t now = simTime();
    for (auto it = brpCoverageTable.begin(); it != brpCoverageTable.end();) {
        if (now - it->second.createTime > brpCoverageLifetime) {
            EV_DETAIL << "BRP: Removing expired coverage entry " << it->first << endl;
            it = brpCoverageTable.erase(it);
        }
        else {
            ++it;
        }
    }
}

void Gzrp::schedulePendingTimer(cMessage* msg, simtime_t delay)
{
    pendingTimers.push_back(msg);
    scheduleAfter(delay, msg);
}

void Gzrp::cancelPendingTimer(cMessage* msg)
{
    auto it = std::find(pendingTimers.begin(), pendingTimers.end(), msg);
    if (it != pendingTimers.end()) {
        pendingTimers.erase(it);
    }
    cancelAndDelete(msg);
}

void Gzrp::cancelAllPendingTimers()
{
    for (auto* msg : pendingTimers) {
        if (msg->getKind() == GZRP_SELF_BRP_JITTER && msg->getContextPointer()) {
            delete static_cast<BRP_Data*>(msg->getContextPointer());
        }
        cancelAndDelete(msg);
    }
    pendingTimers.clear();
}

} // namespace gzrp
} // namespace inet
