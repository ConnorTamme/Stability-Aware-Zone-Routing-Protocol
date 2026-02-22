// Connor Tamme, tammeconnor@gmail.com
//
// Main file of the ZRP implementation. Implements logic for handling and sending messages
//

#include "Zrp.h"
#include "ZrpRouteData.h"

#include <sstream>
#include <iomanip>
#include <set>
#include <algorithm>
#include <queue>

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
#include "inet/transportlayer/contract/udp/UdpControlInfo.h"

namespace inet {
namespace zrp {

Define_Module(Zrp);

Zrp::Zrp()
{
    // This does nothing in AODV, so leaving it blank
}

Zrp::~Zrp()
{
    // Kept erroring when clearing the state so for now leaving it alone since experiments won't be reusing modules
    // anyway clearState();
}

void Zrp::initialize(int stage)
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

        // Parameters and Setup
        NDP_helloTimer = new cMessage("NDP_helloTimer");
        IARP_updateTimer = new cMessage("IARP_updateTimer");
        debugTimer = new cMessage("debugTimer");

        zrpUDPPort = par("udpPort");
        NDP_helloInterval = par("NDP_helloInterval");
        IARP_updateInterval = par("IARP_updateInterval");
        zoneRadius = par("zoneRadius");
        linkStateLifetime = par("linkStateLifetime");
        debugInterval = par("debugInterval");
        brpJitterMax = par("brpJitterMax");
        brpCoverageLifetime = par("brpCoverageLifetime");
        ierpRetryInterval = par("ierpRetryInterval");
        ierpMaxRetries = par("ierpMaxRetries");

        // WATCH variables for Qtenv
        WATCH(zoneRadius);
        WATCH(NDP_seqNum);
        WATCH(IARP_seqNum);
        WATCH_MAP(neighbourTable);
        WATCH_MAP(linkStateTable);
        WATCH(IERP_queryId);
    }
}

// Receiving cMessages
void Zrp::handleMessageWhenUp(cMessage* msg)
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
        else if (msg->getKind() == ZRP_SELF_IERP_RETRY) {
            // Route request retry timer fired
            L3Address dest = L3Address(Ipv4Address(msg->par("destAddr").longValue()));
            EV_INFO << "IERP retry timer for " << dest << endl;

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

                    IERP_initiateRouteDiscovery(dest);
                }
                else {
                    EV_WARN << "IERP: Max retries (" << ierpMaxRetries << ") exhausted for " << dest << ", dropping "
                            << delayedPackets.count(dest) << " buffered packets" << endl;
                    // Drop buffered packets. Need to use dropQueuedDatagram so the
                    // network layer releases them from its hook queue.
                    auto lt = delayedPackets.lower_bound(dest);
                    auto ut = delayedPackets.upper_bound(dest);
                    for (auto it = lt; it != ut; it++) {
                        networkProtocol->dropQueuedDatagram(it->second);
                    }
                    delayedPackets.erase(lt, ut);
                    ierpRetryCounters.erase(dest);
                }
            }
            else {
                // Route was found or no more packets, clean up
                ierpRetryCounters.erase(dest);
            }

            // Remove from retry timers map
            auto tmrIt = ierpRetryTimers.find(dest);
            if (tmrIt != ierpRetryTimers.end() && tmrIt->second == msg) {
                ierpRetryTimers.erase(tmrIt);
            }
            delete msg;
        }
        else if (msg->getKind() == ZRP_SELF_BRP_JITTER) {
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

void Zrp::handleStartOperation(LifecycleOperation* operation)
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

void Zrp::handleStopOperation(LifecycleOperation* operation)
{
    clearState();
}

void Zrp::handleCrashOperation(LifecycleOperation* operation)
{
    clearState();
}

void Zrp::clearState()
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
        delete entry.second;
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
    ierpQueryTable.clear();
    brpCoverageTable.clear();

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

void Zrp::printDebugTables()
{
    std::ostringstream os;

    os << "\n";
    os << "========================================================================\n";
    os << "  ZRP DEBUG OUTPUT - Node: " << getSelfIPAddress() << " @ t=" << simTime() << "\n";
    os << "========================================================================\n";

    // --- Neighbour Table ---
    os << "\n  NEIGHBOR TABLE (" << neighbourTable.size() << " entries):\n";
    os << "  +-----------------+------------------+--------------+\n";
    os << "  | Neighbour        | Last Heard       | Age (sec)    |\n";
    os << "  +-----------------+------------------+--------------+\n";
    if (neighbourTable.empty()) {
        os << "  |            (empty)                               |\n";
    }
    else {
        for (const auto& entry : neighbourTable) {
            double age = (simTime() - entry.second).dbl();
            os << "  | " << std::setw(15) << std::left << entry.first.str() << " | " << std::setw(16) << entry.second
               << " | " << std::setw(12) << std::fixed << std::setprecision(2) << age << " |\n";
        }
    }
    os << "  +-----------------+------------------+--------------+\n";

    // --- Link State Table ---
    os << "\n  LINK STATE TABLE (" << linkStateTable.size() << " entries):\n";
    if (linkStateTable.empty()) {
        os << "    (empty)\n";
    }
    else {
        for (const auto& entry : linkStateTable) {
            const LinkStateEntry& ls = entry.second;
            double age = (simTime() - ls.insertTime).dbl();
            os << "  +-- Source: " << ls.sourceAddr.str() << " (seq=" << ls.seqNum << ", zone=" << ls.zoneRadius
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
            auto* routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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
INetfilter::IHook::Result Zrp::datagramPreRoutingHook(Packet* datagram)
{
    Enter_Method("datagramPreRoutingHook");
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramForwardHook(Packet* datagram)
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

INetfilter::IHook::Result Zrp::datagramPostRoutingHook(Packet* datagram)
{
    Enter_Method("datagramPostRoutingHook");
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramLocalInHook(Packet* datagram)
{
    Enter_Method("datagramLocalInHook");
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramLocalOutHook(Packet* datagram)
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
void Zrp::socketDataArrived(UdpSocket* socket, Packet* packet)
{
    processPacket(packet);
}

void Zrp::socketErrorArrived(UdpSocket* socket, Indication* indication)
{
    EV_WARN << "UDP socket error" << endl;
    delete indication;
}

void Zrp::socketClosed(UdpSocket* socket) {}

void Zrp::receiveSignal(cComponent* source, simsignal_t signalID, cObject* obj, cObject* details)
{
    Enter_Method("receiveSignal");
    if (signalID == linkBrokenSignal) {
        // Link failure. Remove broken neighbour and trigger route maintenance
        Packet* datagram = check_and_cast<Packet*>(obj);
        const auto& networkHeader = findNetworkProtocolHeader(datagram);
        if (networkHeader != nullptr) {
            L3Address unreachableNextHop = networkHeader->getDestinationAddress();
            EV_WARN << "Link break detected to " << unreachableNextHop << endl;

            // Remove from neighbour table immediately
            auto it = neighbourTable.find(unreachableNextHop);
            if (it != neighbourTable.end()) {
                neighbourTable.erase(it);
                EV_INFO << "Removed broken neighbour " << unreachableNextHop << " from neighbour table" << endl;
            }

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

void Zrp::refreshDisplay() const
{
    RoutingProtocolBase::refreshDisplay();

    int numRoutes = getNumIarpRoutes();
    int numNeighbours = neighbourTable.size();
    int numIerpRoutes = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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
int Zrp::getNumIarpRoutes() const
{
    int count = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        if (routingTable->getRoute(i)->getSource() == this) {
            count++;
        }
    }
    return count;
}

L3Address Zrp::getSelfIPAddress() const
{
    return routingTable->getRouterIdAsGeneric();
}

void Zrp::processPacket(Packet* packet)
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
        EV_WARN << "Unknown ZRP packet type received" << endl;
    }

    delete packet;
}

void Zrp::sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl)
{
    const char* className = payload->getClassName();
    Packet* packet = new Packet(!strncmp("inet::", className, 6) ? className + 6 : className, payload);

    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId();

    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<HopLimitReq>()->setHopLimit(ttl);
    packet->addTag<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTag<L4PortReq>()->setDestPort(zrpUDPPort);

    socket.send(packet);
}

// NDP Functions
const Ptr<NDP_Hello> Zrp::createNDPHello()
{
    auto hello = makeShared<NDP_Hello>();

    hello->setNodeAddress(getSelfIPAddress());
    hello->setSeqNum(NDP_seqNum++);

    // L3Address (4B) + seqNum (2B) = 6 bytes
    hello->setChunkLength(B(6));

    return hello;
}

void Zrp::sendNDPHello()
{
    EV_INFO << "Sending NDP Hello from " << getSelfIPAddress() << endl;

    auto hello = createNDPHello();
    sendZrpPacket(hello, Ipv4Address::ALLONES_ADDRESS, 1);

    scheduleAfter(NDP_helloInterval, NDP_helloTimer);
}

void Zrp::handleNDPHello(const Ptr<NDP_Hello>& hello, const L3Address& sourceAddr)
{
    EV_INFO << "Received NDP Hello from " << sourceAddr << " (node address: " << hello->getNodeAddress()
            << ", seq: " << hello->getSeqNum() << ")" << endl;

    // Check if this is a new neighbour
    bool isNew = (neighbourTable.find(sourceAddr) == neighbourTable.end());

    // Update neighbour table with current time
    neighbourTable[sourceAddr] = simTime();

    EV_DETAIL << "Neighbour table now has " << neighbourTable.size() << " entries" << endl;

    // New neighbour. Recompute IARP routes
    if (isNew) {
        EV_INFO << "New neighbour " << sourceAddr << " discovered, recomputing IARP routes" << endl;
        IARP_updateRoutingTable();
    }
}

void Zrp::NDP_refreshNeighbourTable()
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
        EV_DETAIL << "Removed stale neighbour: " << addr << endl;
    }

    EV_INFO << "Neighbour table refresh complete, " << neighbourTable.size() << " neighbours remain" << endl;
}

// IARP Functions
const Ptr<IARP_LinkStateUpdate> Zrp::createIARPUpdate()
{
    auto update = makeShared<IARP_LinkStateUpdate>();

    update->setSourceAddr(getSelfIPAddress());
    update->setSeqNum(IARP_seqNum++);
    update->setRadius(zoneRadius);
    update->setTTL(zoneRadius -
                   1); // Making TTL equal zoneRadius - 1 really threw me off so I
                       // will explain it in detail. Essentially these packets are meant to tell other nodes
                       // in the zone about who this node is connected to. In a network with topology D->A->B->C,
                       // with radius 2. A should about both B and C, and it learns it exclusively from B. You
                       // would think C should be the one to tell A, but this is unnecessary as B's message has both
                       // B itself and also that it is connected to C. Or in other words it has info about nodes that
                       // are 2 hops from A. So if TTL were set to radius then C would hear about D when A sends it's
                       // update packets around which is no good. If TTL is radius - 1 then B hears about D, but that
                       // information never reaches C so it is fine.

    // Probably should have been obvious to me, but all this clicks very nicely when you realize that these
    // updates are NOT in anyway for the node sending them to gain information. They are to inform other nodes
    // about the sender's links, and if everyone is doing that then everyone will learn everything they need to know.

    size_t neighbourCount = neighbourTable.size();
    update->setLinkDestCount(neighbourCount);
    update->setLinkDestDataArraySize(neighbourCount);

    size_t idx = 0;
    for (const auto& neighbour : neighbourTable) {
        IARP_LinkDestData destData;
        destData.addr = neighbour.first;

        // Set metrics - for now just hop count = 1 for direct neighbours
        for (int m = 0; m < IARP_METRIC_COUNT; m++) {
            destData.metrics[m].metricType = 0;  // 0 = hop count
            destData.metrics[m].metricValue = 1; // direct neighbour = 1 hop
        }

        update->setLinkDestData(idx++, destData);
    }

    // Calculate chunk length:
    // Header: sourceAddr(4) + seqNum(2) + radius(1) + TTL(1) + reserved1(2) + reserved2(1) + linkDestCount(1) = 12
    // bytes Per link dest: addr(4) + metrics(IARP_METRIC_COUNT * 4) bytes
    B chunkLength = B(12 + neighbourCount * (4 + IARP_METRIC_COUNT * 4));
    update->setChunkLength(chunkLength);

    return update;
}

void Zrp::sendIARPUpdate()
{
    EV_INFO << "Sending IARP Link State Update from " << getSelfIPAddress() << " with " << neighbourTable.size()
            << " neighbours" << endl;

    if (neighbourTable.empty()) {
        EV_DETAIL << "No neighbours to advertise, skipping IARP update" << endl;
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }

    // If zone radius is 1 we don't need IARP packets as NDP is enough
    if (zoneRadius <= 1) {
        EV_DETAIL << "zoneRadius=1, IARP link-state flooding not needed (NDP suffices)" << endl;
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }

    auto update = createIARPUpdate();
    sendZrpPacket(update, Ipv4Address::ALLONES_ADDRESS, zoneRadius - 1);

    scheduleAfter(IARP_updateInterval, IARP_updateTimer);
}

void Zrp::handleIARPUpdate(const Ptr<IARP_LinkStateUpdate>& update, const L3Address& sourceAddr)
{
    L3Address originatorAddr = update->getSourceAddr();
    uint16_t seqNum = update->getSeqNum();

    EV_INFO << "Received IARP Link State Update from " << sourceAddr << " originated by " << originatorAddr
            << " (seq: " << seqNum << ", TTL: " << (int)update->getTTL() << ")" << endl;

    // Ignore our own updates
    if (originatorAddr == getSelfIPAddress()) {
        EV_DETAIL << "Ignoring own IARP update" << endl;
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
    entry.zoneRadius = update->getRadius();
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

    // Notify IERP of topology change (RFC IERP Section 5.E.1: IARP_updated())
    IERP_routeMaintenance();

    // Decrement TTL and rebroadcast if TTL > 0
    uint8_t ttl = update->getTTL();
    if (ttl > 1) {
        auto fwdUpdate = update->dupShared();
        auto mutableUpdate = CHK(dynamicPtrCast<IARP_LinkStateUpdate>(fwdUpdate));
        mutableUpdate->setTTL(ttl - 1);

        EV_INFO << "Rebroadcasting IARP update with TTL=" << (int)(ttl - 1) << endl;
        sendZrpPacket(mutableUpdate, Ipv4Address::ALLONES_ADDRESS, ttl - 1);
    }
    else {
        EV_DETAIL << "TTL exhausted, not rebroadcasting" << endl;
    }
}

void Zrp::IARP_refreshLinkStateTable()
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

IRoute* Zrp::IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops)
{
    IRoute* newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32); // Host route
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET); // Using MANET as ZRP has no source type in OMNeT++
    newRoute->setSource(this);

    ZrpRouteData* routeData = new ZrpRouteData(ZRP_ROUTE_IARP);
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

void Zrp::IARP_purgeRoutingTable()
{
    // Remove only IARP routes (not IERP routes)
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (!routeData || routeData->isIarpRoute()) {
                EV_DETAIL << "Purging IARP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

void Zrp::IARP_computeRoutes()
{
    // Dijkstra's for shortest paths within the zone
    L3Address self = getSelfIPAddress();

    std::map<L3Address, unsigned int> dist;
    std::map<L3Address, L3Address> nextHop;
    std::set<L3Address> visited;

    // min-heap by distance
    typedef std::pair<unsigned int, L3Address> PQEntry;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> pq;

    dist[self] = 0;
    pq.push({0, self});

    while (!pq.empty()) {
        auto [d, u] = pq.top();
        pq.pop();

        if (visited.count(u)) {
            continue;
        }
        visited.insert(u);

        EV_DETAIL << "Dijkstra: processing node " << u << " at distance " << d << endl;

        if (u != self) {
            IARP_createRoute(u, nextHop[u], d);
        }

        // For self: use neighbourTable, for others: use linkStateTable
        std::vector<std::pair<L3Address, unsigned int>> neighbours;

        if (u == self) {
            for (const auto& entry : neighbourTable) {
                neighbours.push_back({entry.first, 1}); // hop count = 1 for direct neighbours
            }
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations) {
                    // Use first metric (hop count)
                    neighbours.push_back({linkDest.destAddr, linkDest.metrics[0]});
                }
            }
        }

        for (const auto& [v, weight] : neighbours) {
            if (visited.count(v)) {
                continue;
            }

            unsigned int newDist = d + weight;

            if (newDist > zoneRadius) {
                continue;
            }

            if (dist.find(v) == dist.end() || newDist < dist[v]) {
                dist[v] = newDist;

                if (u == self) {
                    nextHop[v] = v;
                }
                else {
                    nextHop[v] = nextHop[u];
                }

                pq.push({newDist, v});
            }
        }
    }
}

std::vector<L3Address> Zrp::IARP_getRoutePath(const L3Address& dest) const
{
    // Dijkstra from self, tracking predecessors to reconstruct the full path.
    // Returns [self, ..., dest] or empty if dest is not in our zone.
    L3Address self = getSelfIPAddress();

    std::map<L3Address, unsigned int> dist;
    std::map<L3Address, L3Address> prev;
    std::set<L3Address> visited;

    typedef std::pair<unsigned int, L3Address> PQEntry;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> pq;

    dist[self] = 0;
    pq.push({0, self});

    while (!pq.empty()) {
        auto [d, u] = pq.top();
        pq.pop();

        if (visited.count(u))
            continue;
        visited.insert(u);

        if (u == dest)
            break; // Found shortest path, done

        std::vector<std::pair<L3Address, unsigned int>> neighbours;
        if (u == self) {
            for (const auto& entry : neighbourTable)
                neighbours.push_back({entry.first, 1});
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations)
                    neighbours.push_back({linkDest.destAddr, linkDest.metrics[0]});
            }
        }

        for (const auto& [v, weight] : neighbours) {
            if (visited.count(v))
                continue;
            unsigned int newDist = d + weight;
            if (newDist > zoneRadius)
                continue;
            if (dist.find(v) == dist.end() || newDist < dist[v]) {
                dist[v] = newDist;
                prev[v] = u;
                pq.push({newDist, v});
            }
        }
    }

    if (!visited.count(dest))
        return {}; // Not reachable within zone

    // Reconstruct path by walking predecessors
    std::vector<L3Address> path;
    for (L3Address cur = dest; cur != self; cur = prev[cur])
        path.push_back(cur);
    path.push_back(self);
    std::reverse(path.begin(), path.end());
    return path;
}

void Zrp::IARP_updateRoutingTable()
{
    EV_INFO << "Updating IARP routing table..." << endl;

    IARP_purgeRoutingTable();

    IARP_computeRoutes();
}

// IERP Functions

void Zrp::IERP_initiateRouteDiscovery(const L3Address& dest)
{
    EV_INFO << "Initiating IERP route discovery for " << dest << endl;

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
        cMessage* retryMsg = new cMessage("IERP_retryTimer", ZRP_SELF_IERP_RETRY);
        retryMsg->addPar("destAddr") = (long)dest.toIpv4().getInt();
        ierpRetryTimers[dest] = retryMsg;
        scheduleAfter(ierpRetryInterval, retryMsg);
    }
}

const Ptr<IERP_RouteData> Zrp::IERP_createRouteRequest(const L3Address& dest)
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

const Ptr<IERP_RouteData> Zrp::IERP_createRouteReply(const Ptr<IERP_RouteData>& request)
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

void Zrp::IERP_handleRouteRequest(const Ptr<IERP_RouteData>& request, const L3Address& sourceAddr)
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
            auto* rd = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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

        if (queryDest != self && ierpRoute) {
            // Destination known via cached IERP source route, append intermediate hops
            auto* rd = dynamic_cast<ZrpRouteData*>(ierpRoute->getProtocolData());
            if (rd && !rd->getSourceRoute().empty()) {
                const auto& srcRoute = rd->getSourceRoute();
                for (size_t i = 1; i < srcRoute.size() - 1; i++) {
                    size_t sz = editableRequest->getIntermediateNodesArraySize();
                    editableRequest->setIntermediateNodesArraySize(sz + 1);
                    editableRequest->setIntermediateNodes(sz, srcRoute[i]);
                }
            }
        }
        else if (queryDest != self && iarpRoute) {
            // Destination in our zone. Append the IARP route
            std::vector<L3Address> iarpPath = IARP_getRoutePath(queryDest);
            // iarpPath = [self, ..., dest]. Skip self (already added) and dest (set by reply).
            for (size_t i = 1; i < iarpPath.size() - 1; i++) {
                size_t sz = editableRequest->getIntermediateNodesArraySize();
                editableRequest->setIntermediateNodesArraySize(sz + 1);
                editableRequest->setIntermediateNodes(sz, iarpPath[i]);
            }
        }

        // Create and send reply
        auto reply = IERP_createRouteReply(editableRequest);

        // Send reply back toward source along the reverse accumulated route.
        // The next hop toward the source is the last intermediate node before us.
        L3Address nextHopToSource;
        if (editableRequest->getIntermediateNodesArraySize() >= 2) {
            // The node just before us in the route
            nextHopToSource =
                editableRequest->getIntermediateNodes(editableRequest->getIntermediateNodesArraySize() - 2);
        }
        else {
            // We are the first hop from source, reply directly
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

void Zrp::IERP_handleRouteReply(const Ptr<IERP_RouteData>& reply, const L3Address& sourceAddr)
{
    // RFC IERP Section 5.E.3: Deliver(packet) - case ROUTE_REPLY
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

    // Install/update route to destination
    if (routeToDest.size() > 1) {
        L3Address nextHop = routeToDest[1];
        unsigned int hops = routeToDest.size() - 1;

        // Remove existing IERP route to this destination if any
        IRoute* existingRoute = IERP_findRoute(routeDest);
        if (existingRoute) {
            routingTable->deleteRoute(existingRoute);
        }

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

void Zrp::IERP_routeMaintenance()
{
    // For each IERP route, try to shorten it using current IARP topology.
    L3Address self = getSelfIPAddress();

    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() != this)
            continue;

        auto* routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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
                    auto* candData = dynamic_cast<ZrpRouteData*>(candidate->getProtocolData());
                    if (candData && candData->isIarpRoute()) {
                        iarpRoute = candidate;
                        break;
                    }
                }
            }

            if (iarpRoute) {
                // We can reach intermediateNode via IARP, shorten the route
                unsigned int iarpHops = iarpRoute->getMetric();
                unsigned int tailHops = sourceRoute.size() - 1 - j;
                unsigned int totalHops = iarpHops + tailHops;

                if (totalHops < minDist) {
                    minDist = totalHops;

                    // Build shortened route (IARP handles hop-by-hop within zone)
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

            // Update the route in the routing table
            route->setNextHop(bestRoute.size() > 1 ? bestRoute[1] : dest);
            route->setMetric(minDist);
            routeData->setSourceRoute(bestRoute);
        }

        // Check if route is still valid (
        L3Address nextHop = route->getNextHopAsGeneric();
        bool nextHopReachable = false;

        // Check if next hop is a direct neighbour
        if (neighbourTable.find(nextHop) != neighbourTable.end()) {
            nextHopReachable = true;
        }
        // Or reachable via IARP
        else {
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute* candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this && candidate->getDestinationAsGeneric() == nextHop) {
                    auto* candData = dynamic_cast<ZrpRouteData*>(candidate->getProtocolData());
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

IRoute* Zrp::IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                              const std::vector<L3Address>& fullRoute)
{
    IRoute* newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32);
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);
    newRoute->setSource(this);

    // Attach ZrpRouteData with IERP type and full source route
    ZrpRouteData* routeData = new ZrpRouteData(ZRP_ROUTE_IERP);
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

void Zrp::IERP_purgeRoutingTable()
{
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                EV_DETAIL << "Purging IERP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

bool Zrp::IERP_hasRouteToDestination(const L3Address& dest) const
{
    return IERP_findRoute(dest) != nullptr;
}

IRoute* Zrp::IERP_findRoute(const L3Address& dest) const
{
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == dest) {
            auto* routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                return route;
            }
        }
    }
    return nullptr;
}

bool Zrp::IERP_hasOngoingDiscovery(const L3Address& dest) const
{
    // Check if we've already sent a query for this destination
    // by looking through our query table for queries we originated
    L3Address self = getSelfIPAddress();
    for (const auto& entry : ierpQueryTable) {
        if (entry.first.source == self && entry.second.destination == dest && !entry.second.replied) {
            return true;
        }
    }
    return false;
}

void Zrp::IERP_delayDatagram(Packet* datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& dest = networkHeader->getDestinationAddress();
    EV_DETAIL << "Buffering datagram for destination " << dest << endl;
    delayedPackets.insert(std::pair<L3Address, Packet*>(dest, datagram));
}

void Zrp::IERP_completeRouteDiscovery(const L3Address& dest)
{
    EV_DETAIL << "Completing route discovery for " << dest << ", releasing " << delayedPackets.count(dest)
              << " buffered datagrams" << endl;

    auto lt = delayedPackets.lower_bound(dest);
    auto ut = delayedPackets.upper_bound(dest);

    // Reinject the delayed datagrams now that a route exists
    for (auto it = lt; it != ut; it++) {
        Packet* datagram = it->second;
        const auto& networkHeader = getNetworkProtocolHeader(datagram);
        EV_DETAIL << "Reinjecting buffered datagram: src=" << networkHeader->getSourceAddress()
                  << ", dest=" << networkHeader->getDestinationAddress() << endl;
        networkProtocol->reinjectQueuedDatagram(datagram);
    }

    delayedPackets.erase(lt, ut);

    // Mark the query as replied
    L3Address self = getSelfIPAddress();
    for (auto& entry : ierpQueryTable) {
        if (entry.first.source == self && entry.second.destination == dest) {
            entry.second.replied = true;
        }
    }

    // Cancel retry timer for this destination
    auto retryIt = ierpRetryTimers.find(dest);
    if (retryIt != ierpRetryTimers.end()) {
        cancelAndDelete(retryIt->second);
        ierpRetryTimers.erase(retryIt);
    }
    ierpRetryCounters.erase(dest);
}

bool Zrp::IERP_isQuerySeen(const IerpQueryId& qid) const
{
    return ierpQueryTable.find(qid) != ierpQueryTable.end();
}

void Zrp::IERP_recordQuery(const IerpQueryId& qid, const L3Address& dest)
{
    IerpQueryRecord record;
    record.queryId = qid;
    record.destination = dest;
    record.receiveTime = simTime();
    record.replied = false;
    ierpQueryTable[qid] = record;
}

void Zrp::IERP_cleanQueryTable()
{
    // Remove stale query records
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

void Zrp::BRP_bordercast(const Ptr<IERP_RouteData>& packet)
{
    L3Address self = getSelfIPAddress();
    L3Address queryDest = packet->getDestAddr();

    // Build the query ID from the IERP packet
    IerpQueryId qid;
    qid.source = packet->getSourceAddr();
    qid.queryId = packet->getQueryID();

    // Resolve coverage by query ID
    int cacheId = BRP_findOrCreateCoverage(qid);

    auto& coverage = brpCoverageTable[cacheId];

    // Determine the set of outgoing neighbours
    std::set<L3Address> outNeighbours;

    // Check if we have an IARP route to the query destination
    bool haveIarpRouteToDest = false;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == queryDest) {
            auto* rd = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (rd && rd->isIarpRoute()) {
                haveIarpRouteToDest = true;
                // If the destination is not already covered, send to next hop toward it
                if (coverage.coveredNodes.find(queryDest) == coverage.coveredNodes.end()) {
                    outNeighbours.insert(route->getNextHopAsGeneric());
                }
                break;
            }
        }
    }

    if (!haveIarpRouteToDest) {
        // Get our peripheral nodes
        std::set<L3Address> peripherals = BRP_getMyPeripherals();

        // Filter to uncovered peripherals
        std::set<L3Address> uncoveredPeripherals;
        for (const auto& p : peripherals) {
            if (coverage.coveredNodes.find(p) == coverage.coveredNodes.end()) {
                uncoveredPeripherals.insert(p);
            }
        }

        EV_DETAIL << "BRP: Peripheral nodes: " << peripherals.size() << ", uncovered: " << uncoveredPeripherals.size()
                  << endl;

        if (!uncoveredPeripherals.empty()) {
            // Get next hop neighbours on shortest paths to uncovered peripherals
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

        // Build BRP packet wrapping the IERP packet
        for (const auto& neighbour : outNeighbours) {
            auto brpPacket = makeShared<BRP_Data>();
            brpPacket->setSourceAddr(qid.source);
            brpPacket->setDestAddr(queryDest);
            brpPacket->setQueryID(qid.queryId);
            brpPacket->setQueryExtension(0);
            brpPacket->setPrevBordercastAddr(self);

            // Encapsulate the IERP packet
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

            // Unicast to each out_neighbour
            sendZrpPacket(brpPacket, neighbour, zoneRadius);
        }
    }

    std::set<L3Address> myZone = BRP_getMyZone();
    BRP_recordCoverage(cacheId, myZone);
}

void Zrp::BRP_deliver(const Ptr<BRP_Data>& brpPacket, const L3Address& sourceAddr)
{
    L3Address self = getSelfIPAddress();
    L3Address prevBordercaster = brpPacket->getPrevBordercastAddr();
    L3Address querySource = brpPacket->getSourceAddr();
    L3Address queryDest = brpPacket->getDestAddr();
    uint16_t queryID = brpPacket->getQueryID();

    EV_INFO << "BRP: Received BRP packet from " << sourceAddr << " (prevBcast=" << prevBordercaster
            << ", query src=" << querySource << ", dest=" << queryDest << ", queryID=" << queryID << ")" << endl;

    // Build query ID
    IerpQueryId qid;
    qid.source = querySource;
    qid.queryId = queryID;

    int cacheId = BRP_findOrCreateCoverage(qid);

    // Check if we are an out_neighbour and compute prevBordercaster's zone
    std::set<L3Address> prevBcastZone;
    bool isOutNbr = BRP_isOutNeighbour(prevBordercaster, self, brpCoverageTable[cacheId].coveredNodes, prevBcastZone);
    BRP_recordCoverage(cacheId, prevBcastZone);

    if (isOutNbr && !brpCoverageTable[cacheId].delivered) {
        // Schedule delivery to IERP with jitter
        brpCoverageTable[cacheId].delivered = true;
        simtime_t jitter = uniform(0, brpJitterMax);

        EV_DETAIL << "BRP: We are an out_neighbour of " << prevBordercaster
                  << ", scheduling IERP delivery with jitter=" << jitter << "s" << endl;

        // Create a self-message carrying the BRP data for when jitter expires
        cMessage* jitterMsg = new cMessage("BRP_jitter", ZRP_SELF_BRP_JITTER);
        jitterMsg->addPar("brpCacheId") = cacheId;

        // Attach BRP packet data via context pointer
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
        // Not an out_neighbour or already scheduled. Just accumulate coverage
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

std::set<L3Address> Zrp::BRP_getMyZone() const
{
    std::set<L3Address> zone;
    zone.insert(getSelfIPAddress());

    // Every IARP route destination is in our zone
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto* rd = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (rd && rd->isIarpRoute()) {
                zone.insert(route->getDestinationAsGeneric());
            }
        }
    }

    return zone;
}

// IARP routes at exactly zoneRadius hops
std::set<L3Address> Zrp::BRP_getMyPeripherals() const
{
    std::set<L3Address> peripherals;

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute* route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getMetric() == zoneRadius) {
            auto* rd = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (rd && rd->isIarpRoute()) {
                peripherals.insert(route->getDestinationAsGeneric());
            }
        }
    }

    return peripherals;
}

// Next hop neighbours for reaching uncovered peripheral nodes
std::set<L3Address> Zrp::BRP_getOutNeighbours(const std::set<L3Address>& uncoveredPeripherals) const
{
    std::set<L3Address> outNeighbours;

    for (const auto& peripheral : uncoveredPeripherals) {
        // Find the IARP route to this peripheral and get its next-hop
        for (int i = 0; i < routingTable->getNumRoutes(); i++) {
            IRoute* route = routingTable->getRoute(i);
            if (route->getSource() == this && route->getDestinationAsGeneric() == peripheral) {
                auto* rd = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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
bool Zrp::BRP_isOutNeighbour(const L3Address& prevBordercaster, const L3Address& node,
                            const std::set<L3Address>& coveredNodes, std::set<L3Address>& outPrevZone) const
{
    // Single Dijkstra from prevBordercaster: computes zone, peripherals, and next-hops
    std::map<L3Address, unsigned int> dist;
    std::map<L3Address, L3Address> nextHop;
    std::set<L3Address> visited;
    std::set<L3Address> peripherals;

    typedef std::pair<unsigned int, L3Address> PQEntry;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> pq;

    dist[prevBordercaster] = 0;
    pq.push({0, prevBordercaster});

    L3Address self = getSelfIPAddress();

    while (!pq.empty()) {
        auto [d, u] = pq.top();
        pq.pop();

        if (visited.count(u))
            continue;
        visited.insert(u);
        outPrevZone.insert(u); // Every visited node is in prevBordercaster's zone

        if (d == zoneRadius) {
            peripherals.insert(u); // Peripheral = exactly at zone radius
            continue;              // Don't expand beyond peripherals
        }

        // Get neighbours of u from best available source.
        // For self use NDP; for others use link-state.
        // Also inject symmetric edge self<->u for NDP neighbours (important for zoneRadius==1
        // since otherwise there is no outgoing edges on those nodes).
        std::vector<std::pair<L3Address, unsigned int>> neighbours;
        if (u == self) {
            for (const auto& entry : neighbourTable)
                neighbours.push_back({entry.first, 1});
        }
        else {
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations)
                    neighbours.push_back({linkDest.destAddr, linkDest.metrics[0]});
            }
            // Ensure symmetric link self<->u when u is our NDP neighbour
            if (neighbourTable.find(u) != neighbourTable.end()) {
                bool selfAlreadyListed = false;
                for (const auto& n : neighbours) {
                    if (n.first == self) {
                        selfAlreadyListed = true;
                        break;
                    }
                }
                if (!selfAlreadyListed)
                    neighbours.push_back({self, 1});
            }
        }

        for (const auto& [v, weight] : neighbours) {
            if (visited.count(v))
                continue;
            unsigned int newDist = d + weight;
            if (newDist > zoneRadius)
                continue;
            if (dist.find(v) == dist.end() || newDist < dist[v]) {
                dist[v] = newDist;
                nextHop[v] = (u == prevBordercaster) ? v : nextHop[u];
                pq.push({newDist, v});
            }
        }
    }

    // Filter peripherals to uncovered only
    // Check if 'node' is the next-hop for any uncovered peripheral
    for (const auto& peripheral : peripherals) {
        if (coveredNodes.find(peripheral) == coveredNodes.end()) {
            if (nextHop.find(peripheral) != nextHop.end() && nextHop[peripheral] == node) {
                return true;
            }
        }
    }

    return false;
}

void Zrp::BRP_recordCoverage(int brpCacheId, const std::set<L3Address>& nodes)
{
    auto it = brpCoverageTable.find(brpCacheId);
    if (it != brpCoverageTable.end()) {
        it->second.coveredNodes.insert(nodes.begin(), nodes.end());
    }
}

int Zrp::BRP_findOrCreateCoverage(const IerpQueryId& qid)
{
    // Check if we already have a coverage entry for this query
    for (auto& entry : brpCoverageTable) {
        if (entry.second.queryId == qid) {
            return entry.first;
        }
    }

    // Create new entry
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

void Zrp::BRP_cleanCoverageTable()
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

void Zrp::schedulePendingTimer(cMessage* msg, simtime_t delay)
{
    pendingTimers.push_back(msg);
    scheduleAfter(delay, msg);
}

void Zrp::cancelPendingTimer(cMessage* msg)
{
    auto it = std::find(pendingTimers.begin(), pendingTimers.end(), msg);
    if (it != pendingTimers.end()) {
        pendingTimers.erase(it);
    }
    cancelAndDelete(msg);
}

void Zrp::cancelAllPendingTimers()
{
    for (auto* msg : pendingTimers) {
        if (msg->getKind() == ZRP_SELF_BRP_JITTER && msg->getContextPointer()) {
            delete static_cast<BRP_Data*>(msg->getContextPointer());
        }
        cancelAndDelete(msg);
    }
    pendingTimers.clear();
}

} // namespace zrp
} // namespace inet
