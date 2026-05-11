//
// Main file of the SAZRP (Stability-Aware ZRP) implementation.
// Implements logic for handling and sending messages.
//

#include "SaZrp.h"
#include "SaZrpRouteData.h"

#include <sstream>
#include <iomanip>
#include <set>
#include <algorithm>
#include <queue>
#include <cmath>
#include <limits>

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
namespace sazrp {

Define_Module(SaZrp);

simsignal_t SaZrp::controlPacketSentSignal = registerSignal("controlPacketSent");
simsignal_t SaZrp::routeDiscoveryStartedSignal = registerSignal("routeDiscoveryStarted");
simsignal_t SaZrp::routeDiscoveryRetriedSignal = registerSignal("routeDiscoveryRetried");
simsignal_t SaZrp::pktSentNDPSignal       = registerSignal("pktSentNDP");
simsignal_t SaZrp::pktSentIARPSignal      = registerSignal("pktSentIARP");
simsignal_t SaZrp::pktSentIERPQuerySignal = registerSignal("pktSentIERPQuery");
simsignal_t SaZrp::pktSentIERPReplySignal = registerSignal("pktSentIERPReply");
simsignal_t SaZrp::pktSentBRPSignal       = registerSignal("pktSentBRP");
simsignal_t SaZrp::routeLengthSignal       = registerSignal("routeLength");
simsignal_t SaZrp::routeDiscoveryTimeSignal = registerSignal("routeDiscoveryTime");

namespace {
// Threshold below which a link is treated as effectively absent by the widest-path
// Dijkstra relaxation: states pushed with sbar near zero cannot contribute to any
// admissible path once decay is applied.
constexpr double STABILITY_EPSILON = 1e-6;

inline double clamp01(double v)
{
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

// Decode a quantized stability byte to a double in [0,1].
inline double decodeStability(uint8_t q)
{
    return static_cast<double>(q) / 255.0;
}

// Encode a stability in [0,1] to a one-byte quantization.
inline uint8_t encodeStability(double s)
{
    double clamped = clamp01(s);
    return static_cast<uint8_t>(std::floor(clamped * 255.0));
}
} // namespace

SaZrp::SaZrp()
{
    // This does nothing in AODV, so leaving it blank
}

SaZrp::~SaZrp()
{
    // Kept erroring when clearing the state so for now leaving it alone since experiments won't be reusing modules
    // anyway clearState();
}

void SaZrp::initialize(int stage)
{
    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        // Register netfilter hooks so datagramLocalOutHook/ForwardHook etc. are invoked
        networkProtocol->registerHook(0, this);
        // Subscribe to link break signals for RERR / route maintenance
        host->subscribe(linkBrokenSignal, this);
    }

    if (stage == INITSTAGE_LOCAL) {
        host = getContainingNode(this);

        // Reference routing table and interface table
        routingTable.reference(this, "routingTableModule", true);
        interfaceTable.reference(this, "interfaceTableModule", true);
        networkProtocol.reference(this, "networkProtocolModule", true);

        // Look up the mobility submodule on the containing node
        mobility = check_and_cast<IMobility*>(host->getSubmodule("mobility"));

        // Parameters and Setup
        NDP_helloTimer = new cMessage("NDP_helloTimer");
        IARP_updateTimer = new cMessage("IARP_updateTimer");
        debugTimer = new cMessage("debugTimer");

        zrpUDPPort = par("udpPort");
        NDP_helloInterval = par("NDP_helloInterval");
        IARP_updateInterval = par("IARP_updateInterval");
        stabilityThreshold = par("stabilityThreshold");
        commsRange = par("commsRange");
        vMax = par("vMax");
        emaAlpha = par("emaAlpha");
        distanceExponent = par("distanceExponent");
        decayBeta = par("decayBeta");
        linkStateLifetime = par("linkStateLifetime");
        debugInterval = par("debugInterval");
        brpJitterMax = par("brpJitterMax");
        brpCoverageLifetime = par("brpCoverageLifetime");
        ierpRetryInterval = par("ierpRetryInterval");
        ierpMaxRetries = par("ierpMaxRetries");
        delayedPacketLifetime = par("delayedPacketLifetime");
        IARP_eventDelay = par("IARP_eventDelay");
        IARP_eventJitter = par("IARP_eventJitter");

        // WATCH variables for Qtenv
        WATCH(stabilityThreshold);
        WATCH(commsRange);
        WATCH(vMax);
        WATCH(emaAlpha);
        WATCH(distanceExponent);
        WATCH(decayBeta);
        WATCH(NDP_seqNum);
        WATCH(IARP_seqNum);
        WATCH_MAP(neighbourTable);
        WATCH_MAP(linkStateTable);
        WATCH_MAP(neighbourStability);
        WATCH(IERP_queryId);
    }
}

// Receiving cMessages
void SaZrp::handleMessageWhenUp(cMessage* msg)
{
    if (msg->isSelfMessage()) {
        if (msg == NDP_helloTimer) {
            NDP_refreshNeighbourTable();
            sendNDPHello();
        }
        else if (msg == IARP_updateTimer) {
            IARP_refreshLinkStateTable();
            sendIARPUpdate();
            // Periodic cleanup of stale query/coverage entries
            IERP_cleanQueryTable();
            BRP_cleanCoverageTable();
        }
        else if (msg == debugTimer) {
            printDebugTables();
            if (debugInterval > 0)
                scheduleAfter(debugInterval, debugTimer);
        }
        else if (msg->getKind() == SAZRP_SELF_IERP_RETRY) {
            // Route request retry timer fired
            L3Address dest = L3Address(Ipv4Address(msg->par("destAddr").longValue()));
            EV_INFO << "IERP retry timer for " << dest << endl;

            // Erase the firing timer from the map BEFORE any call that might
            // try to schedule a new one. IERP_initiateRouteDiscovery only arms
            // a retry if ierpRetryTimers has no entry for this dest, so leaving
            // the stale (firing) entry in place would silently swallow the
            // re-arm and leave subsequent retries unscheduled.
            auto tmrIt = ierpRetryTimers.find(dest);
            if (tmrIt != ierpRetryTimers.end() && tmrIt->second == msg) {
                ierpRetryTimers.erase(tmrIt);
            }

            // Check if we still need a route (no route yet, packets still buffered)
            if (!routingTable->findBestMatchingRoute(dest) && delayedPackets.count(dest) > 0) {
                auto retryIt = ierpRetryCounters.find(dest);
                int retryCount = (retryIt != ierpRetryCounters.end()) ? retryIt->second : 0;

                if (retryCount < (int)ierpMaxRetries) {
                    ierpRetryCounters[dest] = retryCount + 1;
                    EV_INFO << "IERP: Retrying route discovery for " << dest << " (attempt " << (retryCount + 1) << "/"
                            << ierpMaxRetries << ")" << endl;

                    // Clear old query record so we can re-issue
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
                    // Drop buffered packets. Need to use dropQueuedDatagram so the
                    // network layer releases them from its hook queue.
                    auto lt = delayedPackets.lower_bound(dest);
                    auto ut = delayedPackets.upper_bound(dest);
                    for (auto it = lt; it != ut; it++) {
                        networkProtocol->dropQueuedDatagram(it->second.second);
                    }
                    delayedPackets.erase(lt, ut);
                    ierpRetryCounters.erase(dest);
                    // Discovery is being abandoned -- drop the start-time
                    // entry so a future discovery for the same dest doesn't
                    // emit a stale elapsed value.
                    ierpDiscoveryStartTimes.erase(dest);
                }
            }
            else {
                // Route was found or no more packets, clean up
                ierpRetryCounters.erase(dest);
            }

            delete msg;
        }
        else if (msg->getKind() == SAZRP_SELF_BRP_JITTER) {
            // BRP jitter expired, deliver encapsulated packet to IERP
            int brpCacheId = (int)msg->par("brpCacheId").longValue();
            auto* brpDataRaw = static_cast<BRP_Data*>(msg->getContextPointer());

            if (brpDataRaw) {
                // Extract encapsulated IERP packet
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

            // Remove from pending timers list
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
        // Non-self messages come from the UDP socket
        socket.processMessage(msg);
    }
}

void SaZrp::handleStartOperation(LifecycleOperation* operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(L3Address(), zrpUDPPort);
    socket.setBroadcast(true);

    // Send NDP hello with some small jitter so they don't collide
    scheduleAfter(uniform(0, 0.1), NDP_helloTimer);

    // Delay IARP update to ensure NDP_Hello messages are sent first
    scheduleAfter(NDP_helloInterval * 2 + uniform(0, 0.5), IARP_updateTimer);

    // Schedule debug output if enabled
    if (debugInterval > 0)
        scheduleAfter(debugInterval, debugTimer);
}

void SaZrp::handleStopOperation(LifecycleOperation* operation)
{
    clearState();
}

void SaZrp::handleCrashOperation(LifecycleOperation* operation)
{
    clearState();
}

void SaZrp::clearState()
{
    // Cancel and delete fixed self messages
    cancelAndDelete(NDP_helloTimer);
    NDP_helloTimer = nullptr;
    cancelAndDelete(IARP_updateTimer);
    IARP_updateTimer = nullptr;
    cancelAndDelete(debugTimer);
    debugTimer = nullptr;

    // Cancel pending timers
    cancelAllPendingTimers();

    // Drop all buffered datagrams
    for (auto& entry : delayedPackets) {
        delete entry.second.second;
    }
    delayedPackets.clear();

    // Cancel and clean up IERP retry timers
    for (auto& entry : ierpRetryTimers) {
        cancelAndDelete(entry.second);
    }
    ierpRetryTimers.clear();

    // Clear state tables
    neighbourTable.clear();
    linkStateTable.clear();
    neighbourStability.clear();
    neighbourKinematics.clear();
    ierpQueryTable.clear();
    brpCoverageTable.clear();
    ierpDiscoveryStartTimes.clear();

    // Reset sequence numbers
    NDP_seqNum = 0;
    IARP_seqNum = 0;
    IERP_queryId = 0;
    BRP_bordercastId = 0;

    // Clear the routing table
    if (routingTable != nullptr && routingTable.getNullable() != nullptr) {
        IARP_purgeRoutingTable();
        IERP_purgeRoutingTable();
    }
}

void SaZrp::printDebugTables()
{
    std::ostringstream os;

    os << "\n";
    os << "========================================================================\n";
    os << "  SAZRP DEBUG OUTPUT - Node: " << getSelfIPAddress() << " @ t=" << simTime() << "\n";
    os << "========================================================================\n";

    // --- Neighbour Table ---
    os << "\n  NEIGHBOR TABLE (" << neighbourTable.size() << " entries):\n";
    os << "  +-----------------+------------------+--------------+----------+\n";
    os << "  | Neighbour        | Last Heard       | Age (sec)    | sbar     |\n";
    os << "  +-----------------+------------------+--------------+----------+\n";
    if (neighbourTable.empty()) {
        os << "  |            (empty)                                          |\n";
    }
    else {
        for (const auto& entry : neighbourTable) {
            double age = (simTime() - entry.second).dbl();
            double sbar = 0.0;
            auto sIt = neighbourStability.find(entry.first);
            if (sIt != neighbourStability.end()) sbar = sIt->second;
            os << "  | " << std::setw(15) << std::left << entry.first.str() << " | " << std::setw(16) << entry.second
               << " | " << std::setw(12) << std::fixed << std::setprecision(2) << age
               << " | " << std::setw(8) << std::fixed << std::setprecision(3) << sbar << " |\n";
        }
    }
    os << "  +-----------------+------------------+--------------+----------+\n";

    // --- Link State Table ---
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

    // --- Routing Table (IARP routes only) ---
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

    // --- IERP Routes ---
    os << "\n  IERP ROUTES:\n";
    os << "  +-----------------+-----------------+----------+------------------------------+\n";
    os << "  | Destination     | Next Hop        | Hops     | Full Source Route             |\n";
    os << "  +-----------------+-----------------+----------+------------------------------+\n";
    int ierpRouteCount = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                ierpRouteCount++;
                os << "  | " << std::setw(15) << std::left << route->getDestinationAsGeneric().str() << " | "
                   << std::setw(15) << route->getNextHopAsGeneric().str() << " | " << std::setw(8) << route->getMetric()
                   << " | ";
                const auto& srcRoute = routeData->getSourceRoute();
                for (size_t j = 0; j < srcRoute.size(); j++) {
                    if (j > 0)
                        os << "->";
                    os << srcRoute[j].str();
                }
                os << " |\n";
            }
        }
    }
    if (ierpRouteCount == 0) {
        os << "  |        (no IERP routes installed)                                    |\n";
    }
    os << "  +-----------------+-----------------+----------+------------------------------+\n";
    os << "  Total IERP routes: " << ierpRouteCount << "\n";

    // --- IERP Query Table ---
    os << "\n  IERP QUERY TABLE (" << ierpQueryTable.size() << " entries):\n";
    if (!ierpQueryTable.empty()) {
        os << "  +-----------------+----------+-----------------+--------------+\n";
        os << "  | Query Source    | Query ID | Destination     | Age (sec)    |\n";
        os << "  +-----------------+----------+-----------------+--------------+\n";
        for (const auto& entry : ierpQueryTable) {
            double age = (simTime() - entry.second.receiveTime).dbl();
            os << "  | " << std::setw(15) << std::left << entry.first.source.str() << " | " << std::setw(8)
               << entry.first.queryId << " | " << std::setw(15) << entry.second.destination.str() << " | "
               << std::setw(12) << std::fixed << std::setprecision(2) << age << " |\n";
        }
        os << "  +-----------------+----------+-----------------+--------------+\n";
    }
    else {
        os << "    (empty)\n";
    }

    // --- BRP Coverage Table ---
    os << "\n  BRP COVERAGE TABLE (" << brpCoverageTable.size() << " entries):\n";
    if (!brpCoverageTable.empty()) {
        os << "  +----------+-----------------+----------+--------------+---------+\n";
        os << "  | Cache ID | Query Source     | Query ID | Age (sec)    | Covered |\n";
        os << "  +----------+-----------------+----------+--------------+---------+\n";
        for (const auto& entry : brpCoverageTable) {
            double age = (simTime() - entry.second.createTime).dbl();
            os << "  | " << std::setw(8) << entry.first << " | " << std::setw(15) << std::left
               << entry.second.queryId.source.str() << " | " << std::setw(8) << entry.second.queryId.queryId << " | "
               << std::setw(12) << std::fixed << std::setprecision(2) << age << " | " << std::setw(7)
               << entry.second.coveredNodes.size() << " |\n";
        }
        os << "  +----------+-----------------+----------+--------------+---------+\n";
    }
    else {
        os << "    (empty)\n";
    }

    os << "========================================================================\n\n";

    EV_INFO << os.str();
}

// Netfilter hooks
INetfilter::IHook::Result SaZrp::datagramPreRoutingHook(Packet* datagram)
{
    Enter_Method("datagramPreRoutingHook");
    return ACCEPT;
}

INetfilter::IHook::Result SaZrp::datagramForwardHook(Packet* datagram)
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

INetfilter::IHook::Result SaZrp::datagramPostRoutingHook(Packet* datagram)
{
    Enter_Method("datagramPostRoutingHook");
    return ACCEPT;
}

INetfilter::IHook::Result SaZrp::datagramLocalInHook(Packet* datagram)
{
    Enter_Method("datagramLocalInHook");
    return ACCEPT;
}

INetfilter::IHook::Result SaZrp::datagramLocalOutHook(Packet* datagram)
{
    Enter_Method("datagramLocalOutHook");
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    L3Address destAddr = networkHeader->getDestinationAddress();

    if (!destAddr.isBroadcast() && !destAddr.isMulticast() && destAddr != getSelfIPAddress()) {
        IRoute* route = routingTable->findBestMatchingRoute(destAddr);
        if (!route) {
            // No route available. Buffer datagram and initiate discovery
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

// UDP socket stuff
void SaZrp::socketDataArrived(UdpSocket* socket, Packet* packet)
{
    processPacket(packet);
}

void SaZrp::socketErrorArrived(UdpSocket* socket, Indication* indication)
{
    EV_WARN << "UDP socket error" << endl;
    delete indication;
}

void SaZrp::socketClosed(UdpSocket* socket) {}

void SaZrp::receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details)
{
    Enter_Method("receiveSignal");
    if (signalID == linkBrokenSignal) {
        // Link failure. networkHeader->getDestinationAddress() is the FINAL
        // destination of the failed datagram, not the unreachable neighbour.
        // To find the actual broken next hop we look up the route to the dest
        // and read its next hop, mirroring inet/aodv/Aodv.cc:receiveSignal.
        Packet* datagram = check_and_cast<Packet*>(obj);
        const auto& networkHeader = findNetworkProtocolHeader(datagram);
        if (networkHeader != nullptr) {
            L3Address unreachableDest = networkHeader->getDestinationAddress();
            IRoute* failedRoute = routingTable->findBestMatchingRoute(unreachableDest);
            if (failedRoute == nullptr || failedRoute->getSource() != this) {
                EV_DETAIL << "Link break for " << unreachableDest
                          << " but no SaZRP route found; ignoring" << endl;
                return;
            }
            L3Address unreachableNextHop = failedRoute->getNextHopAsGeneric();
            EV_WARN << "Link break detected to next hop " << unreachableNextHop
                    << " (final dest " << unreachableDest << ")" << endl;

            // Remove the actual broken next hop from neighbour table immediately
            auto it = neighbourTable.find(unreachableNextHop);
            if (it != neighbourTable.end()) {
                neighbourTable.erase(it);
                EV_INFO << "Removed broken neighbour " << unreachableNextHop << " from neighbour table" << endl;
            }
            neighbourStability.erase(unreachableNextHop);
            neighbourKinematics.erase(unreachableNextHop);

            // Invalidate any IERP routes using this next hop
            for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
                IRoute* route = routingTable->getRoute(i);
                if (route->getSource() == this && route->getNextHopAsGeneric() == unreachableNextHop) {
                    L3Address dest = route->getDestinationAsGeneric();
                    EV_WARN << "Removing broken route to " << dest << " via " << unreachableNextHop << endl;
                    routingTable->deleteRoute(route);
                }
            }

            // Recompute IARP routes and run IERP maintenance to repair/shorten remaining routes
            IARP_updateRoutingTable();
            IERP_routeMaintenance();
        }
    }
}

void SaZrp::refreshDisplay() const
{
    RoutingProtocolBase::refreshDisplay();

    int numRoutes = getNumIarpRoutes();
    int numNeighbours = neighbourTable.size();
    int numIerpRoutes = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                numIerpRoutes++;
            }
        }
    }

    char buf[80];
    sprintf(buf, "N:%d IA:%d IE:%d", numNeighbours, numRoutes, numIerpRoutes);
    getDisplayString().setTagArg("t", 0, buf); // "t" = text below icon
}

// Helper functions
int SaZrp::getNumIarpRoutes() const
{
    int count = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        if (routingTable->getRoute(i)->getSource() == this) {
            count++;
        }
    }
    return count;
}

L3Address SaZrp::getSelfIPAddress() const
{
    return routingTable->getRouterIdAsGeneric();
}

void SaZrp::processPacket(Packet* packet)
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
        // RFC BRP Section 4.E.2: Deliver(packet) - BRP packet received from IP
        auto mutableBrp = CHK(dynamicPtrCast<BRP_Data>(chunk->dupShared()));
        BRP_deliver(mutableBrp, sourceAddr);
    }
    else {
        EV_WARN << "Unknown SAZRP packet type received" << endl;
    }

    delete packet;
}

void SaZrp::sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl)
{
    const char* className = payload->getClassName();
    Packet* packet = new Packet(!strncmp("inet::", className, 6) ? className + 6 : className, payload);

    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId();

    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<HopLimitReq>()->setHopLimit(ttl);
    packet->addTag<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTag<L4PortReq>()->setDestPort(zrpUDPPort);

    // Aggregate signal: every control packet, all types lumped. Kept for
    // continuity with the existing overhead_ratio metric in extract_metrics.py.
    emit(controlPacketSentSignal, packet);
    // Per-type attribution: dispatch on payload chunk type so the breakdown
    // plot can show NDP / IARP / IERP-query / IERP-reply / BRP separately.
    // Exactly one per-type signal fires per call -- the sum of their counts
    // must equal controlPacketSent:count (a useful sanity check).
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

// NDP Functions
const Ptr<NDP_Hello> SaZrp::createNDPHello()
{
    auto hello = makeShared<NDP_Hello>();

    hello->setNodeAddress(getSelfIPAddress());
    hello->setSeqNum(NDP_seqNum++);

    // Populate position and velocity from the mobility module (required for LPAR)
    const Coord& pos = mobility->getCurrentPosition();
    const Coord& vel = mobility->getCurrentVelocity();
    hello->setPosX(static_cast<float>(pos.x));
    hello->setPosY(static_cast<float>(pos.y));
    hello->setPosZ(static_cast<float>(pos.z));
    hello->setVelX(static_cast<float>(vel.x));
    hello->setVelY(static_cast<float>(vel.y));
    hello->setVelZ(static_cast<float>(vel.z));

    // L3Address (4B) + seqNum (2B) + 6 floats * 4B = 6 + 24 = 30 bytes
    hello->setChunkLength(B(30));

    return hello;
}

void SaZrp::sendNDPHello()
{
    EV_INFO << "Sending NDP Hello from " << getSelfIPAddress() << endl;

    auto hello = createNDPHello();
    sendZrpPacket(hello, Ipv4Address::ALLONES_ADDRESS, 1);

    scheduleAfter(NDP_helloInterval, NDP_helloTimer);
}

void SaZrp::handleNDPHello(const Ptr<NDP_Hello>& hello, const L3Address& sourceAddr)
{
    EV_INFO << "Received NDP Hello from " << sourceAddr << " (node address: " << hello->getNodeAddress()
            << ", seq: " << hello->getSeqNum() << ")" << endl;

    // Check if this is a new neighbour (also a fresh stability sample seed)
    bool isNewNeighbour = (neighbourTable.find(sourceAddr) == neighbourTable.end());
    bool hadStability = (neighbourStability.find(sourceAddr) != neighbourStability.end());

    // Update neighbour table with current time
    neighbourTable[sourceAddr] = simTime();

    EV_DETAIL << "Neighbour table now has " << neighbourTable.size() << " entries" << endl;

    // v2 per-link stability computation: sharper D and re-centred Y.
    Coord senderPos(hello->getPosX(), hello->getPosY(), hello->getPosZ());
    Coord senderVel(hello->getVelX(), hello->getVelY(), hello->getVelZ());

    Coord selfPos = mobility->getCurrentPosition();
    Coord selfVel = mobility->getCurrentVelocity();

    Coord disp = selfPos - senderPos;       // vector from sender to self
    double d = disp.length();                // Euclidean distance
    Coord relVel = selfVel - senderVel;      // relative velocity
    double Vrel = relVel.length();

    // Sign of the rate of change of d: d/dt |p_self - p_sender| has the sign of
    // (p_self - p_sender) . (v_self - v_sender). Positive => diverging (u = -1),
    // negative => converging (u = +1), zero => constant (u = 0).
    double dot = disp.x * relVel.x + disp.y * relVel.y + disp.z * relVel.z;
    int u = 0;
    if (dot > 0.0) u = -1;
    else if (dot < 0.0) u = +1;

    double D = clamp01(1.0 - std::pow(d / commsRange, distanceExponent));
    double Y = (u != -1) ? 1.0 : clamp01(1.0 - Vrel / (2.0 * vMax));
    double s = D * Y;

    double sbar;
    if (!hadStability) {
        // First sample from this neighbour: seed EMA directly.
        sbar = s;
    }
    else {
        sbar = emaAlpha * s + (1.0 - emaAlpha) * neighbourStability[sourceAddr];
    }

    neighbourStability[sourceAddr] = sbar;
    neighbourKinematics[sourceAddr] = std::make_pair(senderPos, senderVel);

    EV_DETAIL << "Stability: d=" << d << " Vrel=" << Vrel << " u=" << u
              << " D=" << D << " Y=" << Y << " s=" << s << " sbar=" << sbar << endl;

    // New neighbour. Recompute IARP routes
    if (isNewNeighbour) {
        EV_INFO << "New neighbour " << sourceAddr << " discovered, recomputing IARP routes" << endl;
        IARP_updateRoutingTable();
        scheduleEarlyIARPUpdate();
    }
}

void SaZrp::NDP_refreshNeighbourTable()
{
    EV_INFO << "Refreshing neighbour table..." << endl;

    simtime_t now = simTime();
    std::vector<L3Address> toRemove;

    for (const auto& entry : neighbourTable) {
        if (now - entry.second > linkStateLifetime) {
            toRemove.push_back(entry.first);
        }
    }

    for (const auto& addr : toRemove) {
        neighbourTable.erase(addr);
        neighbourStability.erase(addr);
        neighbourKinematics.erase(addr);
        EV_DETAIL << "Removed stale neighbour: " << addr << endl;
    }

    EV_INFO << "Neighbour table refresh complete, " << neighbourTable.size() << " neighbours remain" << endl;

    if (!toRemove.empty()) {
        IARP_updateRoutingTable();
        scheduleEarlyIARPUpdate();
    }
}

// IARP Functions
const Ptr<IARP_LinkStateUpdate> SaZrp::createIARPUpdate()
{
    auto update = makeShared<IARP_LinkStateUpdate>();

    update->setSourceAddr(getSelfIPAddress());
    update->setSeqNum(IARP_seqNum++);
    update->setRadius(0); // unused in SAZRP; kept for layout parity
    // runningStability starts at 255 (encodes 1.0) at the originator.
    update->setRunningStability(255);

    size_t neighbourCount = neighbourTable.size();
    update->setLinkDestCount(neighbourCount);
    update->setLinkDestDataArraySize(neighbourCount);

    size_t idx = 0;
    for (const auto& neighbour : neighbourTable) {
        IARP_LinkDestData destData;
        destData.addr = neighbour.first;

        // Report the quantized smoothed stability for this neighbour.
        double sbar = 0.0;
        auto sIt = neighbourStability.find(neighbour.first);
        if (sIt != neighbourStability.end()) sbar = sIt->second;

        for (int m = 0; m < IARP_METRIC_COUNT; m++) {
            destData.metrics[m].metricType = IARP_METRIC_STABILITY;
            destData.metrics[m].metricValue = static_cast<uint16_t>(encodeStability(sbar));
        }

        update->setLinkDestData(idx++, destData);
    }

    // Header: sourceAddr(4) + seqNum(2) + radius(1) + runningStability(1) + reserved1(2) + reserved2(1) + linkDestCount(1) = 12 bytes
    // Per link dest: addr(4) + metrics(IARP_METRIC_COUNT * 4) bytes
    B chunkLength = B(12 + neighbourCount * (4 + IARP_METRIC_COUNT * 4));
    update->setChunkLength(chunkLength);

    return update;
}

void SaZrp::sendIARPUpdate()
{
    EV_INFO << "Sending IARP Link State Update from " << getSelfIPAddress() << " with " << neighbourTable.size()
            << " neighbours" << endl;

    if (neighbourTable.empty()) {
        EV_DETAIL << "No neighbours to advertise, skipping IARP update" << endl;
        iarpUpdatePending = false;
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }

    auto update = createIARPUpdate();
    // Use a generous IP TTL; flood termination is governed by runningStability, not IP TTL.
    sendZrpPacket(update, Ipv4Address::ALLONES_ADDRESS, 255);

    iarpUpdatePending = false;
    scheduleAfter(IARP_updateInterval, IARP_updateTimer);
}

void SaZrp::scheduleEarlyIARPUpdate()
{
    if (iarpUpdatePending)
        return;
    iarpUpdatePending = true;
    if (IARP_updateTimer->isScheduled())
        cancelEvent(IARP_updateTimer);
    // Add some jitter to ensure messages do not collide
    scheduleAfter(SimTime((int64_t)std::round(IARP_eventDelay + uniform(0, IARP_eventJitter)), SIMTIME_MS), IARP_updateTimer);

}

void SaZrp::handleIARPUpdate(const Ptr<IARP_LinkStateUpdate>& update, const L3Address& sourceAddr)
{
    L3Address originatorAddr = update->getSourceAddr();
    uint16_t seqNum = update->getSeqNum();

    EV_INFO << "Received IARP Link State Update from " << sourceAddr << " originated by " << originatorAddr
            << " (seq: " << seqNum << ", runningStability: " << (int)update->getRunningStability() << ")" << endl;

    // Ignore our own updates
    if (originatorAddr == getSelfIPAddress()) {
        EV_DETAIL << "Ignoring own IARP update" << endl;
        return;
    }

    // Decode the incoming running stability and combine with our link stability to sender.
    double r_in = decodeStability(update->getRunningStability());

    auto sIt = neighbourStability.find(sourceAddr);
    if (sIt == neighbourStability.end()) {
        // No stability sample for the transmitting neighbour yet (Hello not processed).
        EV_DETAIL << "Dropping IARP update: no stability sample for sender " << sourceAddr << endl;
        return;
    }
    double sbar_self_j = sIt->second;

    // Symmetrize the J<->self link: also consult J's last-advertised view of self,
    // if cached, and take the min with our view. Falls back to the asymmetric rule
    // when we have not yet seen an advertisement from J that lists us.
    double sbar_link = sbar_self_j;
    auto jLsIt = linkStateTable.find(sourceAddr);
    if (jLsIt != linkStateTable.end()) {
        L3Address self = getSelfIPAddress();
        for (const auto& ld : jLsIt->second.linkDestinations) {
            if (ld.destAddr == self) {
                double sbar_j_self = static_cast<double>(ld.metrics[0]) / 255.0;
                sbar_link = std::min(sbar_self_j, sbar_j_self);
                break;
            }
        }
    }

    double r_out = decayBeta * std::min(r_in, sbar_link);

    if (r_out < stabilityThreshold) {
        EV_DETAIL << "Dropping IARP update: r_out=" << r_out << " < tau=" << stabilityThreshold << endl;
        return;
    }

    auto it = linkStateTable.find(originatorAddr);
    if (it != linkStateTable.end()) {
        if (!seqNumIsNewer(seqNum, it->second.seqNum)) {
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

    EV_DETAIL << "Updated link state table, now has " << linkStateTable.size() << " entries" << endl;

    // Recompute routing table with new link state information
    IARP_updateRoutingTable();

    // Notify IERP of topology change
    IERP_routeMaintenance();

    // Rebroadcast with the new running stability.
    auto fwdUpdate = update->dupShared();
    auto mutableUpdate = CHK(dynamicPtrCast<IARP_LinkStateUpdate>(fwdUpdate));
    mutableUpdate->setRunningStability(encodeStability(r_out));

    EV_INFO << "Rebroadcasting IARP update with runningStability=" << (int)mutableUpdate->getRunningStability()
            << " (r_out=" << r_out << ")" << endl;
    sendZrpPacket(mutableUpdate, Ipv4Address::ALLONES_ADDRESS, 255);
}

void SaZrp::IARP_refreshLinkStateTable()
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

    // Update routing table after removing stale entries
    IARP_updateRoutingTable();

    // Report topology changes to IERP for route maintenance
    IERP_routeMaintenance();
}

IRoute* SaZrp::IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                                const std::vector<L3Address>& fullRoute)
{
    IRoute* newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32); // Host route
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);
    newRoute->setSource(this);

    SaZrpRouteData* routeData = new SaZrpRouteData(SAZRP_ROUTE_IARP);
    routeData->setSourceRoute(fullRoute);
    routeData->setDiscoveryTime(simTime());
    newRoute->setProtocolData(routeData);

    NetworkInterface* ifEntry = interfaceTable->findInterfaceByName(par("interface"));
    if (ifEntry) {
        newRoute->setInterface(ifEntry);
    }

    EV_DETAIL << "Adding IARP route to " << dest << " via " << nextHop << " (hops: " << hops << ")" << endl;
    routingTable->addRoute(newRoute);

    return newRoute;
}

void SaZrp::IARP_purgeRoutingTable()
{
    // Remove only IARP routes (not IERP routes)
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (!routeData || routeData->isIarpRoute()) {
                EV_DETAIL << "Purging IARP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

void SaZrp::IARP_computeRoutes()
{
    // Widest-path-with-decay Dijkstra. A node v is admitted iff there exists a
    // path P from self to v with beta^|P| * min_{(i,j) in P} sbar_ij >= tau.
    // Direct neighbours are admitted unconditionally (one-hop guarantee).
    L3Address self = getSelfIPAddress();

    struct DijkstraState {
        double value;      // running stability r along best path found so far
        unsigned int hops; // hop count along that same path
        L3Address prev;
    };

    std::map<L3Address, DijkstraState> state;
    std::set<L3Address> visited;

    // Max-heap on (value, address) using default less comparator.
    typedef std::pair<double, L3Address> PQEntry;
    std::priority_queue<PQEntry> pq;

    state[self] = {1.0, 0, self};
    pq.push({1.0, self});

    while (!pq.empty()) {
        auto top = pq.top();
        pq.pop();
        double r = top.first;
        L3Address u = top.second;

        if (visited.count(u))
            continue;
        visited.insert(u);

        EV_DETAIL << "IARP Dijkstra: visit " << u << " value=" << r << " hops=" << state[u].hops << endl;

        if (u != self) {
            // Reconstruct path
            std::vector<L3Address> path;
            for (L3Address cur = u; cur != self; cur = state[cur].prev)
                path.push_back(cur);
            path.push_back(self);
            std::reverse(path.begin(), path.end());

            L3Address nextHop = path.size() > 1 ? path[1] : u;
            IARP_createRoute(u, nextHop, state[u].hops, path);
        }

        // Build neighbour list for u with per-link stabilities.
        std::vector<std::pair<L3Address, double>> neighbours; // (addr, sbar)

        if (u == self) {
            for (const auto& entry : neighbourTable) {
                double sbar = 0.0;
                auto sIt = neighbourStability.find(entry.first);
                if (sIt != neighbourStability.end()) sbar = sIt->second;
                neighbours.push_back({entry.first, sbar});
            }
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations) {
                    // metrics[0] is quantized stability byte
                    double sbar = static_cast<double>(linkDest.metrics[0]) / 255.0;
                    // Symmetrize: also consult v's advertisement for u, if available, and take the min.
                    auto vLsIt = linkStateTable.find(linkDest.destAddr);
                    if (vLsIt != linkStateTable.end()) {
                        for (const auto& reverseDest : vLsIt->second.linkDestinations) {
                            if (reverseDest.destAddr == u) {
                                double sbarReverse = static_cast<double>(reverseDest.metrics[0]) / 255.0;
                                sbar = std::min(sbar, sbarReverse);
                                break;
                            }
                        }
                    }
                    neighbours.push_back({linkDest.destAddr, sbar});
                }
            }
        }

        for (const auto& np : neighbours) {
            const L3Address& v = np.first;
            double sbar = np.second;
            if (visited.count(v))
                continue;

            bool isDirectFromSelf = (u == self) && (neighbourTable.find(v) != neighbourTable.end());

            // Treat effectively-zero stability as a hard zero to avoid pushing useless states.
            if (sbar < STABILITY_EPSILON && !isDirectFromSelf)
                continue;

            double newValue = decayBeta * std::min(state[u].value, sbar);
            unsigned int newHops = state[u].hops + 1;

            // Admission: direct neighbours always pass; others require newValue >= tau.
            if (!isDirectFromSelf && newValue < stabilityThreshold)
                continue;

            auto sit = state.find(v);
            double currentValue = (sit == state.end()) ? 0.0 : sit->second.value;
            if (newValue > currentValue) {
                state[v] = {newValue, newHops, u};
                pq.push({newValue, v});
            }
        }
    }
}

void SaZrp::IARP_updateRoutingTable()
{
    EV_INFO << "Updating IARP routing table..." << endl;

    IARP_purgeRoutingTable();

    IARP_computeRoutes();
}

// IERP Functions

void SaZrp::IERP_initiateRouteDiscovery(const L3Address& dest, bool isRetry)
{
    EV_INFO << (isRetry ? "Retrying" : "Initiating")
            << " IERP route discovery for " << dest << endl;

    // Only the first attempt counts as a "started" discovery -- this matches
    // INET's AODV semantics, where the routeDiscoveryStarted signal fires once
    // per destination and the up-to-rreqRetries retransmits don't refire it.
    if (isRetry)
        emit(routeDiscoveryRetriedSignal, (intval_t)1);
    else {
        emit(routeDiscoveryStartedSignal, (intval_t)1);
        // Record wallclock start of this discovery for the routeDiscoveryTime
        // metric. Retries do NOT reset this -- the metric measures end-user
        // wait time, which spans the whole retry chain. If a stale entry
        // happens to be sitting here (previous discovery never completed),
        // overwrite it: the in-flight one wins.
        ierpDiscoveryStartTimes[dest] = simTime();
    }

    auto request = IERP_createRouteRequest(dest);

    // Record this query so we recognize replies and don't loop
    IerpQueryId qid;
    qid.source = getSelfIPAddress();
    qid.queryId = request->getQueryID();
    IERP_recordQuery(qid, dest);

    // Call BRP to bordercast the route request
    BRP_bordercast(request);

    // Schedule retry timer in case the route request is lost
    if (ierpRetryTimers.find(dest) == ierpRetryTimers.end()) {
        cMessage* retryMsg = new cMessage("IERP_retryTimer", SAZRP_SELF_IERP_RETRY);
        retryMsg->addPar("destAddr") = (long)dest.toIpv4().getInt();
        ierpRetryTimers[dest] = retryMsg;
        scheduleAfter(ierpRetryInterval, retryMsg);
    }
}

const Ptr<IERP_RouteData> SaZrp::IERP_createRouteRequest(const L3Address& dest)
{
    auto request = makeShared<IERP_RouteData>();

    request->setType(IERP_QUERY);
    request->setNodePtr(0); // Points to current position in route (starts at 0)
    request->setQueryID(IERP_queryId++);
    request->setSourceAddr(getSelfIPAddress());
    request->setDestAddr(dest);
    request->setIntermediateNodesArraySize(0); // No intermediate nodes yet

    // Length: type(1) + length(1) + nodePtr(1) + reserved(1) + queryID(2) + reserved(2) +
    //         sourceAddr(4) + destAddr(4) = 16 bytes base
    request->setLength(4); // 16 bytes / 4 = 4 words
    request->setChunkLength(B(16));

    EV_DETAIL << "Created IERP ROUTE_REQUEST: src=" << getSelfIPAddress() << ", dest=" << dest
              << ", queryID=" << request->getQueryID() << endl;

    return request;
}

const Ptr<IERP_RouteData> SaZrp::IERP_createRouteReply(const Ptr<IERP_RouteData>& request)
{
    auto reply = makeShared<IERP_RouteData>();

    reply->setType(IERP_REPLY);
    reply->setQueryID(request->getQueryID());
    reply->setSourceAddr(request->getSourceAddr());
    reply->setDestAddr(request->getDestAddr());

    // Copy the accumulated intermediate nodes from the request
    size_t reqIntermediateCount = request->getIntermediateNodesArraySize();
    reply->setIntermediateNodesArraySize(reqIntermediateCount);
    for (size_t i = 0; i < reqIntermediateCount; i++) {
        reply->setIntermediateNodes(i, request->getIntermediateNodes(i));
    }

    reply->setNodePtr(reqIntermediateCount); // We are at the end of the accumulated route

    // Calculate length
    size_t totalNodes = reqIntermediateCount;
    uint8_t lengthInWords = (16 + totalNodes * 4) / 4;
    reply->setLength(lengthInWords);
    reply->setChunkLength(B(16 + totalNodes * 4));

    EV_DETAIL << "Created IERP ROUTE_REPLY: src=" << reply->getSourceAddr() << ", dest=" << reply->getDestAddr()
              << ", queryID=" << reply->getQueryID() << ", route length=" << totalNodes << " intermediates" << endl;

    return reply;
}

void SaZrp::IERP_handleRouteRequest(const Ptr<IERP_RouteData>& request, const L3Address& sourceAddr)
{
    L3Address self = getSelfIPAddress();
    L3Address querySource = request->getSourceAddr();
    L3Address queryDest = request->getDestAddr();
    uint16_t queryID = request->getQueryID();

    EV_INFO << "IERP: Received ROUTE_REQUEST from " << sourceAddr << " (query src=" << querySource
            << ", dest=" << queryDest << ", queryID=" << queryID << ")" << endl;

    // Ignore requests we originated
    if (querySource == self) {
        EV_DETAIL << "IERP: Ignoring our own route request" << endl;
        return;
    }

    // Check for duplicate queries
    IerpQueryId qid;
    qid.source = querySource;
    qid.queryId = queryID;

    if (IERP_isQuerySeen(qid)) {
        EV_DETAIL << "IERP: Ignoring duplicate route request (already seen queryID=" << queryID << " from "
                  << querySource << ")" << endl;
        return;
    }

    // Also check if our address appears in the accumulated route
    for (size_t i = 0; i < request->getIntermediateNodesArraySize(); i++) {
        if (request->getIntermediateNodes(i) == self) {
            EV_DETAIL << "IERP: Loop detected, our address already in route" << endl;
            return;
        }
    }

    // Record this query
    IERP_recordQuery(qid, queryDest);

    // Record reverse route back to query source
    std::vector<L3Address> routeToSource;
    routeToSource.push_back(self);
    for (int i = (int)request->getIntermediateNodesArraySize() - 1; i >= 0; i--) {
        routeToSource.push_back(request->getIntermediateNodes(i));
    }
    routeToSource.push_back(querySource);

    // Only install reverse IERP route if source isn't already reachable via IARP
    if (!routingTable->findBestMatchingRoute(querySource) && !IERP_hasRouteToDestination(querySource)) {
        L3Address nextHop = routeToSource.size() > 1 ? routeToSource[1] : querySource;
        IERP_createRoute(querySource, nextHop, routeToSource.size() - 1, routeToSource);
    }

    // Check if we can answer: are we the destination, or do we have a route?
    // Check IARP first (intrazone), then IERP (interzone cached routes).
    IRoute* iarpRoute = nullptr;
    IRoute* ierpRoute = nullptr;

    if (queryDest != self) {
        for (int i = 0; i < routingTable->getNumRoutes(); i++) {
            IRoute* route = routingTable->getRoute(i);
            if (route->getSource() != this || route->getDestinationAsGeneric() != queryDest)
                continue;
            auto* rd = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (!rd || rd->isIarpRoute()) {
                iarpRoute = route;
                break; // IARP is preferred, stop looking
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

        // Add our address to intermediate nodes
        size_t currentSize = editableRequest->getIntermediateNodesArraySize();
        editableRequest->setIntermediateNodesArraySize(currentSize + 1);
        editableRequest->setIntermediateNodes(currentSize, self);
        editableRequest->setNodePtr(currentSize + 1);

        IRoute* chosenRoute = iarpRoute ? iarpRoute : ierpRoute;
        if (queryDest != self && chosenRoute) {
            // srcRoute = [self, ..., dest]. Skip self (already added) and dest (set by reply).
            auto* rd = dynamic_cast<SaZrpRouteData*>(chosenRoute->getProtocolData());
            if (rd) {
                const auto& srcRoute = rd->getSourceRoute();
                for (size_t i = 1; i + 1 < srcRoute.size(); i++) {
                    size_t sz = editableRequest->getIntermediateNodesArraySize();
                    editableRequest->setIntermediateNodesArraySize(sz + 1);
                    editableRequest->setIntermediateNodes(sz, srcRoute[i]);
                }
            }
        }

        // Create and send reply
        auto reply = IERP_createRouteReply(editableRequest);

        // Send reply back toward source along the reverse accumulated route.
        L3Address nextHopToSource;
        if (editableRequest->getIntermediateNodesArraySize() >= 2) {
            nextHopToSource =
                editableRequest->getIntermediateNodes(editableRequest->getIntermediateNodesArraySize() - 2);
        }
        else {
            nextHopToSource = querySource;
        }

        // Send via IP directly (not bordercast)
        sendZrpPacket(reply, nextHopToSource, 255);
    }
    else {
        EV_INFO << "IERP: No route to " << queryDest << ", forwarding ROUTE_REQUEST" << endl;

        auto mutableRequest = request->dupShared();
        auto editableRequest = CHK(dynamicPtrCast<IERP_RouteData>(mutableRequest));

        // Add our address to the accumulated route
        size_t currentSize = editableRequest->getIntermediateNodesArraySize();
        editableRequest->setIntermediateNodesArraySize(currentSize + 1);
        editableRequest->setIntermediateNodes(currentSize, self);
        editableRequest->setNodePtr(currentSize + 1);

        // Update length
        size_t totalNodes = editableRequest->getIntermediateNodesArraySize();
        uint8_t lengthInWords = (16 + totalNodes * 4) / 4;
        editableRequest->setLength(lengthInWords);
        editableRequest->setChunkLength(B(16 + totalNodes * 4));

        BRP_bordercast(editableRequest);
    }
}

void SaZrp::IERP_handleRouteReply(const Ptr<IERP_RouteData>& reply, const L3Address& sourceAddr)
{
    L3Address self = getSelfIPAddress();
    L3Address routeSource = reply->getSourceAddr();
    L3Address routeDest = reply->getDestAddr();
    uint16_t queryID = reply->getQueryID();

    EV_INFO << "IERP: Received ROUTE_REPLY from " << sourceAddr << " (route src=" << routeSource
            << ", dest=" << routeDest << ", queryID=" << queryID << ")" << endl;

    // Build full route: source -> intermediates -> destination
    std::vector<L3Address> fullRoute;
    fullRoute.push_back(routeSource);
    for (size_t i = 0; i < reply->getIntermediateNodesArraySize(); i++) {
        fullRoute.push_back(reply->getIntermediateNodes(i));
    }
    fullRoute.push_back(routeDest);

    // Find our position in the route
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

    // Record route toward destination from our position
    std::vector<L3Address> routeToDest;
    for (size_t i = myPos; i < fullRoute.size(); i++) {
        routeToDest.push_back(fullRoute[i]);
    }

    // Install/update route to destination. Tiebreak between competing replies
    // is: (1) high-stability next hop beats low-stability, (2) on the same
    // tier, fewer hops wins, (3) on a full tie, keep the existing route
    // (earlier-arriving wins). Stability tier of a next hop is high iff
    // sbar >= tau OR the neighbour is unknown to neighbourStability (no sample
    // yet -- treat as high so we don't penalise replies whose first hop we
    // simply haven't heard a Hello from in this session).
    if (routeToDest.size() > 1) {
        L3Address nextHop = routeToDest[1];
        unsigned int hops = routeToDest.size() - 1;

        auto isLowStabNextHop = [&](const L3Address& nh) {
            auto sIt = neighbourStability.find(nh);
            return (sIt != neighbourStability.end()) && (sIt->second < stabilityThreshold);
        };

        IRoute* existingRoute = IERP_findRoute(routeDest);
        bool shouldInstall = true;
        if (existingRoute) {
            L3Address oldNextHop = existingRoute->getNextHopAsGeneric();
            unsigned int oldHops = existingRoute->getMetric();
            bool newLow = isLowStabNextHop(nextHop);
            bool oldLow = isLowStabNextHop(oldNextHop);
            if (newLow != oldLow) {
                shouldInstall = !newLow; // prefer the high-stability tier
            }
            else {
                shouldInstall = (hops < oldHops); // same tier -> fewer hops, else keep old
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
        // Decrement node pointer and forward to previous hop (toward source)
        auto fwdReply = reply->dupShared();
        auto editableReply = CHK(dynamicPtrCast<IERP_RouteData>(fwdReply));

        uint8_t nodePtr = editableReply->getNodePtr();
        if (nodePtr > 0) {
            nodePtr--;
            editableReply->setNodePtr(nodePtr);
        }

        // Determine next hop toward source
        L3Address nextHopToSource;
        if (myPos > 1) {
            nextHopToSource = fullRoute[myPos - 1];
        }
        else {
            nextHopToSource = routeSource;
        }

        EV_INFO << "IERP: Forwarding ROUTE_REPLY toward source via " << nextHopToSource << endl;

        // Send directly via IP (not bordercast)
        sendZrpPacket(editableReply, nextHopToSource, 255);
    }
    else {
        EV_INFO << "IERP: ROUTE_REPLY reached query source. Route discovery complete for " << routeDest << endl;
        // Release any datagrams we buffered while waiting for this route
        IERP_completeRouteDiscovery(routeDest);
    }
}

void SaZrp::IERP_routeMaintenance()
{
    // For each IERP route, try to shorten it using current IARP topology.
    L3Address self = getSelfIPAddress();

    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() != this)
            continue;

        auto* routeData = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
        if (!routeData || !routeData->isIerpRoute())
            continue;

        const std::vector<L3Address>& sourceRoute = routeData->getSourceRoute();
        if (sourceRoute.size() < 2)
            continue;

        L3Address dest = route->getDestinationAsGeneric();

        // Try to shorten the route by finding IARP paths to downstream nodes
        unsigned int minDist = sourceRoute.size() - 1; // current hop count
        std::vector<L3Address> bestRoute = sourceRoute;
        bool improved = false;

        for (size_t j = 1; j < sourceRoute.size(); j++) {
            L3Address intermediateNode = sourceRoute[j];

            // Check if we have an IARP route to this intermediate node
            IRoute* iarpRoute = nullptr;
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute* candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this && candidate->getDestinationAsGeneric() == intermediateNode) {
                    auto* candData = dynamic_cast<SaZrpRouteData*>(candidate->getProtocolData());
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

        // Check if route is still valid
        L3Address nextHop = route->getNextHopAsGeneric();
        bool nextHopReachable = false;

        if (neighbourTable.find(nextHop) != neighbourTable.end()) {
            nextHopReachable = true;
        }
        else {
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute* candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this && candidate->getDestinationAsGeneric() == nextHop) {
                    auto* candData = dynamic_cast<SaZrpRouteData*>(candidate->getProtocolData());
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

IRoute* SaZrp::IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                                const std::vector<L3Address>& fullRoute)
{
    IRoute* newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32);
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);
    newRoute->setSource(this);

    SaZrpRouteData* routeData = new SaZrpRouteData(SAZRP_ROUTE_IERP);
    routeData->setSourceRoute(fullRoute);
    routeData->setDiscoveryTime(simTime());
    newRoute->setProtocolData(routeData);

    NetworkInterface* ifEntry = interfaceTable->findInterfaceByName(par("interface"));
    if (ifEntry) {
        newRoute->setInterface(ifEntry);
    }

    EV_DETAIL << "Adding IERP route to " << dest << " via " << nextHop << " (" << hops << " hops)" << endl;
    routingTable->addRoute(newRoute);

    return newRoute;
}

void SaZrp::IERP_purgeRoutingTable()
{
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                EV_DETAIL << "Purging IERP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

bool SaZrp::IERP_hasRouteToDestination(const L3Address& dest) const
{
    return IERP_findRoute(dest) != nullptr;
}

IRoute* SaZrp::IERP_findRoute(const L3Address& dest) const
{
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == dest) {
            auto* routeData = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                return route;
            }
        }
    }
    return nullptr;
}

bool SaZrp::IERP_hasOngoingDiscovery(const L3Address& dest) const
{
    L3Address self = getSelfIPAddress();
    for (const auto& entry : ierpQueryTable) {
        if (entry.first.source == self && entry.second.destination == dest && !entry.second.replied) {
            return true;
        }
    }
    return false;
}

void SaZrp::IERP_delayDatagram(Packet* datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& dest = networkHeader->getDestinationAddress();
    EV_DETAIL << "Buffering datagram for destination " << dest << endl;
    delayedPackets.insert({dest, {simTime(), datagram}});
}

void SaZrp::IERP_completeRouteDiscovery(const L3Address& dest)
{
    EV_DETAIL << "Completing route discovery for " << dest << ", releasing " << delayedPackets.count(dest)
              << " buffered datagrams" << endl;

    // Emit per-discovery metrics on the FIRST reply only. The start-time map
    // entry is created in IERP_initiateRouteDiscovery (non-retry path) and
    // erased here, so subsequent replies for the same query don't re-emit.
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
    // Reinject the delayed datagrams now that a route exists, but drop any
    // that have already aged past delayedPacketLifetime so we don't deliver
    // packets that have been sitting in the queue longer than the application
    // could reasonably want.
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

bool SaZrp::IERP_isQuerySeen(const IerpQueryId& qid) const
{
    return ierpQueryTable.find(qid) != ierpQueryTable.end();
}

void SaZrp::IERP_recordQuery(const IerpQueryId& qid, const L3Address& dest)
{
    IerpQueryRecord record;
    record.queryId = qid;
    record.destination = dest;
    record.receiveTime = simTime();
    record.replied = false;
    ierpQueryTable[qid] = record;
}

void SaZrp::IERP_cleanQueryTable()
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

// BRP Functions

void SaZrp::BRP_bordercast(const Ptr<IERP_RouteData>& packet)
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
            auto* rd = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
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
        EV_INFO << "BRP: No uncovered peripheral nodes to bordercast to" << endl;
    }
    else {
        printDebugTables();
        EV_INFO << "BRP: Bordercasting to " << outNeighbours.size() << " neighbour(s): ";
        for (const auto& n : outNeighbours)
            EV_INFO << n << " ";
        EV_INFO << endl;

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

            // BRP header: source(4) + dest(4) + queryID(2) + queryExt(1) + reserved(1) + prevBcast(4) = 16 bytes
            brpPacket->setChunkLength(B(16) + packet->getChunkLength());

            // Generous IP TTL; the bordercast target handles intrazone forwarding.
            sendZrpPacket(brpPacket, neighbour, 255);
        }
    }

    std::set<L3Address> myZone = BRP_getMyZone();
    BRP_recordCoverage(cacheId, myZone);
}

void SaZrp::BRP_deliver(const Ptr<BRP_Data>& brpPacket, const L3Address& sourceAddr)
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

    if (isOutNbr && !brpCoverageTable[cacheId].delivered) {
        brpCoverageTable[cacheId].delivered = true;
        simtime_t jitter = uniform(0, brpJitterMax);

        EV_DETAIL << "BRP: We are an out_neighbour of " << prevBordercaster
                  << ", scheduling IERP delivery with jitter=" << jitter << "s" << endl;

        cMessage* jitterMsg = new cMessage("BRP_jitter", SAZRP_SELF_BRP_JITTER);
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

std::set<L3Address> SaZrp::BRP_getMyZone() const
{
    std::set<L3Address> zone;
    zone.insert(getSelfIPAddress());

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* rd = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
            if (rd && rd->isIarpRoute()) {
                zone.insert(route->getDestinationAsGeneric());
            }
        }
    }

    return zone;
}

// Peripheral under the stability-aware zone: a zone member that has at least
// one neighbour (as visible in neighbourTable or linkStateTable) outside the zone.
std::set<L3Address> SaZrp::BRP_getMyPeripherals() const
{
    std::set<L3Address> peripherals;
    std::set<L3Address> zone = BRP_getMyZone();
    L3Address self = getSelfIPAddress();

    for (const auto& v : zone) {
        if (v == self)
            continue;

        // Get v's one-hop neighbour set from available topology info.
        std::set<L3Address> vNbrs;

        // v's known neighbours from its link-state advertisement (if we have one).
        auto lsIt = linkStateTable.find(v);
        if (lsIt != linkStateTable.end()) {
            for (const auto& ld : lsIt->second.linkDestinations) {
                vNbrs.insert(ld.destAddr);
            }
        }

        // If v is our direct neighbour, we are also one of v's neighbours.
        if (neighbourTable.find(v) != neighbourTable.end()) {
            vNbrs.insert(self);
        }

        // A neighbour outside the zone makes v a peripheral.
        bool hasOutOfZoneNeighbour = false;
        for (const auto& n : vNbrs) {
            if (zone.find(n) == zone.end()) {
                hasOutOfZoneNeighbour = true;
                break;
            }
        }

        if (hasOutOfZoneNeighbour)
            peripherals.insert(v);
    }

    return peripherals;
}

std::set<L3Address> SaZrp::BRP_getOutNeighbours(const std::set<L3Address>& uncoveredPeripherals) const
{
    std::set<L3Address> outNeighbours;

    for (const auto& peripheral : uncoveredPeripherals) {
        for (int i = 0; i < routingTable->getNumRoutes(); i++) {
            IRoute* route = routingTable->getRoute(i);
            if (route->getSource() == this && route->getDestinationAsGeneric() == peripheral) {
                auto* rd = dynamic_cast<SaZrpRouteData*>(route->getProtocolData());
                if (rd && rd->isIarpRoute()) {
                    outNeighbours.insert(route->getNextHopAsGeneric());
                    break;
                }
            }
        }
    }

    return outNeighbours;
}

// Check if 'node' is an outgoing neighbour in prevBordercaster's bordercast tree.
// Also outputs prevBordercaster's zone (computed as byproduct of Dijkstra).
bool SaZrp::BRP_isOutNeighbour(const L3Address& prevBordercaster, const L3Address& node,
                               const std::set<L3Address>& coveredNodes, std::set<L3Address>& outPrevZone) const
{
    // Widest-path-with-decay Dijkstra from prevBordercaster.
    // Admission: node v is in prevBordercaster's zone iff value_v >= tau.
    // Direct neighbours of prevBordercaster are admitted unconditionally (one-hop guarantee).
    struct SState {
        double value;
        L3Address nextHop;
    };
    std::map<L3Address, SState> state;
    std::set<L3Address> visited;

    typedef std::pair<double, L3Address> PQEntry;
    std::priority_queue<PQEntry> pq;

    state[prevBordercaster] = {1.0, prevBordercaster};
    pq.push({1.0, prevBordercaster});

    L3Address self = getSelfIPAddress();

    // Collect prevBordercaster's one-hop neighbour set (from our view) so we can
    // enforce the one-hop guarantee for edges starting at prevBordercaster.
    std::set<L3Address> prevOneHop;
    if (prevBordercaster == self) {
        for (const auto& entry : neighbourTable) prevOneHop.insert(entry.first);
    }
    else {
        auto it0 = linkStateTable.find(prevBordercaster);
        if (it0 != linkStateTable.end()) {
            for (const auto& ld : it0->second.linkDestinations) prevOneHop.insert(ld.destAddr);
        }
        if (neighbourTable.find(prevBordercaster) != neighbourTable.end()) {
            // We are a neighbour of prevBordercaster
            prevOneHop.insert(self);
        }
    }

    while (!pq.empty()) {
        auto top = pq.top();
        pq.pop();
        double r = top.first;
        L3Address u = top.second;

        if (visited.count(u))
            continue;
        visited.insert(u);
        outPrevZone.insert(u);

        // Build neighbour list for u with per-link stabilities.
        std::vector<std::pair<L3Address, double>> neighbours;
        if (u == self) {
            for (const auto& entry : neighbourTable) {
                double sbar = 0.0;
                auto sIt = neighbourStability.find(entry.first);
                if (sIt != neighbourStability.end()) sbar = sIt->second;
                neighbours.push_back({entry.first, sbar});
            }
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations) {
                    double sbar = static_cast<double>(linkDest.metrics[0]) / 255.0;
                    // Symmetrize: also consult v's advertisement for u, if available, and take the min.
                    auto vLsIt = linkStateTable.find(linkDest.destAddr);
                    if (vLsIt != linkStateTable.end()) {
                        for (const auto& reverseDest : vLsIt->second.linkDestinations) {
                            if (reverseDest.destAddr == u) {
                                double sbarReverse = static_cast<double>(reverseDest.metrics[0]) / 255.0;
                                sbar = std::min(sbar, sbarReverse);
                                break;
                            }
                        }
                    }
                    neighbours.push_back({linkDest.destAddr, sbar});
                }
            }
            // Ensure symmetric link self<->u when u is our NDP neighbour (matches baseline behaviour).
            if (neighbourTable.find(u) != neighbourTable.end()) {
                bool selfAlreadyListed = false;
                for (const auto& n : neighbours) {
                    if (n.first == self) {
                        selfAlreadyListed = true;
                        break;
                    }
                }
                if (!selfAlreadyListed) {
                    double sbar = 0.0;
                    auto sIt = neighbourStability.find(u);
                    if (sIt != neighbourStability.end()) sbar = sIt->second;
                    neighbours.push_back({self, sbar});
                }
            }
        }

        for (const auto& np : neighbours) {
            const L3Address& v = np.first;
            double sbar = np.second;
            if (visited.count(v))
                continue;

            bool isDirectFromPrev = (u == prevBordercaster) && (prevOneHop.find(v) != prevOneHop.end());

            // Treat effectively-zero stability as a hard zero to avoid pushing useless states.
            if (sbar < STABILITY_EPSILON && !isDirectFromPrev)
                continue;

            double newValue = decayBeta * std::min(r, sbar);

            if (!isDirectFromPrev && newValue < stabilityThreshold)
                continue;

            auto sit = state.find(v);
            double currentValue = (sit == state.end()) ? 0.0 : sit->second.value;
            if (newValue > currentValue) {
                L3Address nh = (u == prevBordercaster) ? v : state[u].nextHop;
                state[v] = {newValue, nh};
                pq.push({newValue, v});
            }
        }
    }

    // Derive peripherals under the stability-aware rule: zone members with at least
    // one out-of-zone neighbour (as visible in our topology view).
    std::set<L3Address> peripherals;
    for (const auto& v : outPrevZone) {
        if (v == prevBordercaster)
            continue;

        std::set<L3Address> vNbrs;
        auto lsIt = linkStateTable.find(v);
        if (lsIt != linkStateTable.end()) {
            for (const auto& ld : lsIt->second.linkDestinations) vNbrs.insert(ld.destAddr);
        }
        if (neighbourTable.find(v) != neighbourTable.end()) {
            vNbrs.insert(self);
        }

        for (const auto& n : vNbrs) {
            if (outPrevZone.find(n) == outPrevZone.end()) {
                peripherals.insert(v);
                break;
            }
        }
    }

    // 'node' is an out_neighbour if it is the next-hop for any uncovered peripheral.
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

void SaZrp::BRP_recordCoverage(int brpCacheId, const std::set<L3Address>& nodes)
{
    auto it = brpCoverageTable.find(brpCacheId);
    if (it != brpCoverageTable.end()) {
        it->second.coveredNodes.insert(nodes.begin(), nodes.end());
    }
}

int SaZrp::BRP_findOrCreateCoverage(const IerpQueryId& qid)
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

void SaZrp::BRP_cleanCoverageTable()
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

// Pending Timer Management

void SaZrp::schedulePendingTimer(cMessage* msg, simtime_t delay)
{
    pendingTimers.push_back(msg);
    scheduleAfter(delay, msg);
}

void SaZrp::cancelPendingTimer(cMessage* msg)
{
    auto it = std::find(pendingTimers.begin(), pendingTimers.end(), msg);
    if (it != pendingTimers.end()) {
        pendingTimers.erase(it);
    }
    cancelAndDelete(msg);
}

void SaZrp::cancelAllPendingTimers()
{
    for (auto* msg : pendingTimers) {
        if (msg->getKind() == SAZRP_SELF_BRP_JITTER && msg->getContextPointer()) {
            delete static_cast<BRP_Data*>(msg->getContextPointer());
        }
        cancelAndDelete(msg);
    }
    pendingTimers.clear();
}

} // namespace sazrp
} // namespace inet
