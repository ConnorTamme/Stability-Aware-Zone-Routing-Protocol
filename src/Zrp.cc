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

#include "Zrp.h"
#include "ZrpRouteData.h"

#include <sstream>  // for std::ostringstream in debug output
#include <iomanip>  // for std::setw, std::setprecision in debug output
#include <set>

#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
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

using namespace inet;

namespace zrp {

Define_Module(Zrp);

Zrp::Zrp() {
    // TODO Auto-generated constructor stub
    //This should allow me to get the neighbors using the MAC meaning no hello messages needed
    //cModule *nic = getParentModule()->getSubmodule("wlan", 0)->getSubmodule("mac");
    //does nothing in AODV
}

Zrp::~Zrp() {
    // TODO Auto-generated destructor stub
    //need to clear state info and clear self messages according to AODV
}

void Zrp::initialize(int stage)
{
    if (stage == INITSTAGE_ROUTING_PROTOCOLS){
        //addressType = getSelfIPAddress().getAddressType();
    }

    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        host = getContainingNode(this);

        //Reference routing table and interface table
        routingTable.reference(this, "routingTableModule", true);
        interfaceTable.reference(this, "interfaceTableModule", true);
        networkProtocol.reference(this, "networkProtocolModule", true);

        //Parameters and Setup
        NDP_helloTimer = new cMessage("NDP_helloTimer");
        IARP_updateTimer = new cMessage("IARP_updateTimer");
        debugTimer = new cMessage("debugTimer");

        zrpUDPPort = par("udpPort");
        NDP_helloInterval = par("NDP_helloInterval");
        IARP_updateInterval = par("IARP_updateInterval");
        zoneRadius = par("zoneRadius");
        linkStateLifetime = par("linkStateLifetime");
        debugInterval = par("debugInterval");

        // WATCH variables for GUI inspection
        // In Qtenv, double-click on a node's app[0] to see these values
        WATCH(zoneRadius);
        WATCH(NDP_seqNum);
        WATCH(IARP_seqNum);
        WATCH_MAP(neighborTable);      // Shows all neighbors and last-heard times
        WATCH_MAP(linkStateTable);     // Shows all link state entries
        WATCH(IERP_queryId);
    }
}

//Receiving cMessages
void Zrp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == NDP_helloTimer) {
            NDP_refreshNeighborTable();
            sendNDPHello();
        }
        else if (msg == IARP_updateTimer) {
            IARP_refreshLinkStateTable();
            sendIARPUpdate();
        }
        else if (msg == debugTimer) {
            printDebugTables();
            if (debugInterval > 0)
                scheduleAfter(debugInterval, debugTimer);
        }
        else if (msg->getKind() == ZRP_SELF_BRP_JITTER) {
            // BRP jitter timer expired - deliver the encapsulated IERP packet.
            // For now this is a stub; BRP implementation will populate this.
            // The message's context pointer can carry the bordercast data.
            EV_INFO << "BRP jitter timer expired (stub)" << endl;
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

void Zrp::handleStartOperation(LifecycleOperation *operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(L3Address(), zrpUDPPort);
    socket.setBroadcast(true);

    // Send first NDP hello immediately (with small random jitter to avoid synchronization)
    // This allows neighbors to be discovered before the first IARP update
    scheduleAfter(uniform(0, 0.1), NDP_helloTimer);
    
    // Delay IARP update until after neighbors have a chance to be discovered
    // Use 2x hello interval to ensure at least one hello round-trip completes
    scheduleAfter(NDP_helloInterval * 2 + uniform(0, 0.5), IARP_updateTimer);
    
    // Schedule debug output if enabled
    if (debugInterval > 0)
        scheduleAfter(debugInterval, debugTimer);
}

void Zrp::handleStopOperation(LifecycleOperation *operation)
{
    // TODO: Clean up state
    clearState();
}

void Zrp::handleCrashOperation(LifecycleOperation *operation)
{
    // TODO: Clean up state
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
    
    // Cancel all dynamically created pending timers (BRP jitter, route timeouts, etc.)
    cancelAllPendingTimers();
    
    // Drop all buffered datagrams
    for (auto& entry : delayedPackets) {
        delete entry.second;
    }
    delayedPackets.clear();
    
    // Clear state tables
    neighborTable.clear();
    linkStateTable.clear();
    ierpQueryTable.clear();
    
    // Reset sequence numbers
    NDP_seqNum = 0;
    IARP_seqNum = 0;
    IERP_queryId = 0;

    //Clear routing tables (both IARP and IERP routes)
    IARP_purgeRoutingTable();
    IERP_purgeRoutingTable();
}

void Zrp::printDebugTables()
{
    std::ostringstream os;
    
    os << "\n";
    os << "========================================================================\n";
    os << "  ZRP DEBUG OUTPUT - Node: " << getSelfIPAddress() << " @ t=" << simTime() << "\n";
    os << "========================================================================\n";
    
    // --- Neighbor Table ---
    os << "\n  NEIGHBOR TABLE (" << neighborTable.size() << " entries):\n";
    os << "  +-----------------+------------------+--------------+\n";
    os << "  | Neighbor        | Last Heard       | Age (sec)    |\n";
    os << "  +-----------------+------------------+--------------+\n";
    if (neighborTable.empty()) {
        os << "  |            (empty)                               |\n";
    } else {
        for (const auto& entry : neighborTable) {
            double age = (simTime() - entry.second).dbl();
            os << "  | " << std::setw(15) << std::left << entry.first.str()
               << " | " << std::setw(16) << entry.second
               << " | " << std::setw(12) << std::fixed << std::setprecision(2) << age << " |\n";
        }
    }
    os << "  +-----------------+------------------+--------------+\n";
    
    // --- Link State Table ---
    os << "\n  LINK STATE TABLE (" << linkStateTable.size() << " entries):\n";
    if (linkStateTable.empty()) {
        os << "    (empty)\n";
    } else {
        for (const auto& entry : linkStateTable) {
            const LinkStateEntry& ls = entry.second;
            double age = (simTime() - ls.insertTime).dbl();
            os << "  +-- Source: " << ls.sourceAddr.str()
               << " (seq=" << ls.seqNum << ", zone=" << ls.zoneRadius
               << ", age=" << std::fixed << std::setprecision(1) << age << "s)\n";
            os << "  |   Neighbors (" << ls.linkDestinations.size() << "):\n";
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
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            routeCount++;
            os << "  | " << std::setw(15) << std::left << route->getDestinationAsGeneric().str()
               << " | " << std::setw(15) << route->getNextHopAsGeneric().str()
               << " | " << std::setw(8) << route->getMetric() << " |\n";
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
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto *routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                ierpRouteCount++;
                os << "  | " << std::setw(15) << std::left << route->getDestinationAsGeneric().str()
                   << " | " << std::setw(15) << route->getNextHopAsGeneric().str()
                   << " | " << std::setw(8) << route->getMetric() << " | ";
                const auto& srcRoute = routeData->getSourceRoute();
                for (size_t j = 0; j < srcRoute.size(); j++) {
                    if (j > 0) os << "->";
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
            os << "  | " << std::setw(15) << std::left << entry.first.source.str()
               << " | " << std::setw(8) << entry.first.queryId
               << " | " << std::setw(15) << entry.second.destination.str()
               << " | " << std::setw(12) << std::fixed << std::setprecision(2) << age << " |\n";
        }
        os << "  +-----------------+----------+-----------------+--------------+\n";
    } else {
        os << "    (empty)\n";
    }
    
    os << "========================================================================\n\n";
    
    EV_INFO << os.str();
}

//Netfilter hooks
INetfilter::IHook::Result Zrp::datagramPreRoutingHook(Packet *datagram)
{
    Enter_Method("datagramPreRoutingHook");
    // TODO: Ensure route exists for incoming datagrams
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramForwardHook(Packet *datagram)
{
    Enter_Method("datagramForwardHook");
    // TODO: Handle forwarding, check routes
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramPostRoutingHook(Packet *datagram)
{
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramLocalInHook(Packet *datagram)
{
    return ACCEPT;
}

INetfilter::IHook::Result Zrp::datagramLocalOutHook(Packet *datagram)
{
    Enter_Method("datagramLocalOutHook");
    // When a locally-originated datagram has no route, trigger IERP route discovery
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    L3Address destAddr = networkHeader->getDestinationAddress();

    // Check if we have any route to this destination
    if (!destAddr.isBroadcast() && !destAddr.isMulticast()) {
        IRoute *route = routingTable->findBestMatchingRoute(destAddr);
        if (!route) {
            // No route available - buffer datagram and initiate discovery
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

/* UDP callback interface */
void Zrp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    processPacket(packet);
}

void Zrp::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "UDP socket error" << endl;
    delete indication;
}

void Zrp::socketClosed(UdpSocket *socket)
{
    // Socket closed
}

//cListener
void Zrp::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method("receiveSignal");
    // TODO: Handle link breakage signals
}

// Visual display update - shows neighbor/zone info on node icon
void Zrp::refreshDisplay() const
{
    RoutingProtocolBase::refreshDisplay();

    // Count IARP routes (nodes in zone)
    int numRoutes = getNumIarpRoutes();
    int numNeighbors = neighborTable.size();
    int numLinkStates = linkStateTable.size();
    
    // Count IERP routes
    int numIerpRoutes = 0;
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto *routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (routeData && routeData->isIerpRoute()) {
                numIerpRoutes++;
            }
        }
    }

    // Update display string to show: Neighbors / Zone nodes / IERP routes
    char buf[80];
    sprintf(buf, "N:%d Z:%d R:%d I:%d", numNeighbors, numLinkStates, numRoutes, numIerpRoutes);
    getDisplayString().setTagArg("t", 0, buf);  // "t" = text below icon
}

//Helper functions
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

void Zrp::processPacket(Packet *packet)
{
    //Get source address from packet tag
    L3Address sourceAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
    
    // Peek at the packet content to determine type
    auto chunk = packet->peekAtFront<FieldsChunk>();
    
    // Try to cast to various packet types
    if (auto ndpHello = dynamicPtrCast<const inet::zrp::NDP_Hello>(chunk)) {
        handleNDPHello(CHK(dynamicPtrCast<inet::zrp::NDP_Hello>(chunk->dupShared())), sourceAddr);
    }
    else if (auto iarpUpdate = dynamicPtrCast<const inet::zrp::IARP_LinkStateUpdate>(chunk)) {
        handleIARPUpdate(CHK(dynamicPtrCast<inet::zrp::IARP_LinkStateUpdate>(chunk->dupShared())), sourceAddr);
    }
    else if (auto ierpPacket = dynamicPtrCast<const inet::zrp::IERP_RouteData>(chunk)) {
        auto mutableIerp = CHK(dynamicPtrCast<inet::zrp::IERP_RouteData>(chunk->dupShared()));
        uint8_t type = mutableIerp->getType();
        if (type == inet::zrp::IERP_QUERY) {
            IERP_handleRouteRequest(mutableIerp, sourceAddr);
        }
        else if (type == inet::zrp::IERP_REPLY) {
            IERP_handleRouteReply(mutableIerp, sourceAddr);
        }
        else {
            EV_WARN << "Unknown IERP packet type: " << (int)type << endl;
        }
    }
    else if (auto brpPacket = dynamicPtrCast<const inet::zrp::BRP_Data>(chunk)) {
        // BRP packet received - extract encapsulated IERP packet and process
        // For now: just extract and handle the encapsulated IERP directly
        // Full BRP handling (coverage tracking, jitter, bordercast trees) will be added later
        EV_INFO << "Received BRP packet from " << sourceAddr << " (BRP handling is stub)" << endl;
        auto mutableBrp = CHK(dynamicPtrCast<inet::zrp::BRP_Data>(chunk->dupShared()));
        
        // Extract the encapsulated IERP packet and handle it
        const auto& encapIerp = mutableBrp->getEncapsulatedPacket();
        auto ierpCopy = makeShared<inet::zrp::IERP_RouteData>();
        // Copy fields from encapsulated packet
        ierpCopy->setType(encapIerp.getType());
        ierpCopy->setLength(encapIerp.getLength());
        ierpCopy->setNodePtr(encapIerp.getNodePtr());
        ierpCopy->setQueryID(encapIerp.getQueryID());
        ierpCopy->setSourceAddr(encapIerp.getSourceAddr());
        ierpCopy->setDestAddr(encapIerp.getDestAddr());
        ierpCopy->setIntermediateNodesArraySize(encapIerp.getIntermediateNodesArraySize());
        for (size_t i = 0; i < encapIerp.getIntermediateNodesArraySize(); i++) {
            ierpCopy->setIntermediateNodes(i, encapIerp.getIntermediateNodes(i));
        }
        ierpCopy->setChunkLength(encapIerp.getChunkLength());
        
        uint8_t type = ierpCopy->getType();
        if (type == inet::zrp::IERP_QUERY) {
            IERP_handleRouteRequest(ierpCopy, sourceAddr);
        }
        else if (type == inet::zrp::IERP_REPLY) {
            IERP_handleRouteReply(ierpCopy, sourceAddr);
        }
    }
    else {
        EV_WARN << "Unknown ZRP packet type received" << endl;
    }
    
    delete packet;
}

void Zrp::sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl)
{
    // Create packet with the payload
    const char *className = payload->getClassName();
    Packet *packet = new Packet(!strncmp("inet::", className, 6) ? className + 6 : className, payload);
    
    // Get interface ID
    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId();
    
    // Add required tags
    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<HopLimitReq>()->setHopLimit(ttl);
    packet->addTag<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTag<L4PortReq>()->setDestPort(zrpUDPPort);
    
    // Send via UDP socket
    socket.send(packet);
}

// NDP Functions
const Ptr<inet::zrp::NDP_Hello> Zrp::createNDPHello()
{
    auto hello = makeShared<inet::zrp::NDP_Hello>();
    
    // Set packet fields
    hello->setNodeAddress(getSelfIPAddress());
    hello->setSeqNum(NDP_seqNum++);
    
    // Set chunk length: L3Address (4 bytes for IPv4) + seqNum (2 bytes) = 6 bytes
    hello->setChunkLength(B(6));
    
    return hello;
}

void Zrp::sendNDPHello()
{
    EV_INFO << "Sending NDP Hello from " << getSelfIPAddress() << endl;
    
    // Create and send hello message as broadcast with TTL=1 (neighbors only)
    auto hello = createNDPHello();
    sendZrpPacket(hello, Ipv4Address::ALLONES_ADDRESS, 1);
    
    // Reschedule the timer
    scheduleAfter(NDP_helloInterval, NDP_helloTimer);
}

void Zrp::handleNDPHello(const Ptr<inet::zrp::NDP_Hello>& hello, const L3Address& sourceAddr)
{
    EV_INFO << "Received NDP Hello from " << sourceAddr 
            << " (node address: " << hello->getNodeAddress() 
            << ", seq: " << hello->getSeqNum() << ")" << endl;
    
    // Update neighbor table with current time
    neighborTable[sourceAddr] = simTime();
    
    EV_DETAIL << "Neighbor table now has " << neighborTable.size() << " entries" << endl;
}

void Zrp::NDP_refreshNeighborTable()
{
    EV_INFO << "Refreshing neighbor table..." << endl;
    
    simtime_t now = simTime();
    std::vector<L3Address> toRemove;
    
    // Identify neighbors that have not sent hello within lifetime
    for (const auto& entry : neighborTable) {
        if (now - entry.second > linkStateLifetime) {
            toRemove.push_back(entry.first);
        }
    }
    
    // Remove stale neighbors
    for (const auto& addr : toRemove) {
        neighborTable.erase(addr);
        EV_DETAIL << "Removed stale neighbor: " << addr << endl;
    }
    
    EV_INFO << "Neighbor table refresh complete, " << neighborTable.size() << " neighbors remain" << endl;
}

// IARP Functions
const Ptr<inet::zrp::IARP_LinkStateUpdate> Zrp::createIARPUpdate()
{
    auto update = makeShared<inet::zrp::IARP_LinkStateUpdate>();
    
    // Set packet fields per RFC
    update->setSourceAddr(getSelfIPAddress());
    update->setSeqNum(IARP_seqNum++); // TODO: Potentially an issue when seq nums wrap around
    update->setRadius(zoneRadius);
    update->setTTL(zoneRadius - 1);  // Making TTL equal zoneRadius - 1 really threw me off so I
        // will explain it in detail. Essentially these packets are meant to tell other nodes
        // in the zone about who this node is connected to. In a network with topology D->A->B->C,
        // with radius 2. A should about both B and C, and it learns it exclusively from B. You
        // would think C should be the one to tell A, but this is unnecessary as B's message has both
        // B itself and also that it is connected to C. Or in other words it has info about nodes that
        // are 2 hops from A. So if TTL were set to radius then C would hear about D when A sends it's update
        // packets around which is no good. If TTL is radius - 1 then B hears about D, but that information never
        // reaches C so it is fine.

        //Probably should have been obvious to me, but all this clicks very nicely when you realize that these
        // updates are NOT in anyway for the node sending them to gain information. They are to inform other nodes
        // about the sender's links, and if everyone is doing that then everyone will learn everything they need to know.
    
    // Populate link destinations from neighbor table
    size_t neighborCount = neighborTable.size();
    update->setLinkDestCount(neighborCount);
    update->setLinkDestDataArraySize(neighborCount);
    
    size_t idx = 0;
    for (const auto& neighbor : neighborTable) {
        inet::zrp::IARP_LinkDestData destData;
        destData.addr = neighbor.first;
        
        // Set metrics - for now just hop count = 1 for direct neighbors
        for (int m = 0; m < IARP_METRIC_COUNT; m++) {
            destData.metrics[m].metricType = 0;  // 0 = hop count
            destData.metrics[m].metricValue = 1; // direct neighbor = 1 hop
        }
        
        update->setLinkDestData(idx++, destData);
    }
    
    // Calculate chunk length:
    // Header: sourceAddr(4) + seqNum(2) + radius(1) + TTL(1) + reserved1(2) + reserved2(1) + linkDestCount(1) = 12 bytes
    // Per link dest: addr(4) + metrics(IARP_METRIC_COUNT * 4) bytes
    B chunkLength = B(12 + neighborCount * (4 + IARP_METRIC_COUNT * 4));
    update->setChunkLength(chunkLength);
    
    return update;
}

void Zrp::sendIARPUpdate()
{
    EV_INFO << "Sending IARP Link State Update from " << getSelfIPAddress() 
            << " with " << neighborTable.size() << " neighbors" << endl;
    
    if (neighborTable.empty()) {
        EV_DETAIL << "No neighbors to advertise, skipping IARP update" << endl;
        // Still reschedule the timer
        scheduleAfter(IARP_updateInterval, IARP_updateTimer);
        return;
    }
    
    auto update = createIARPUpdate();
    sendZrpPacket(update, Ipv4Address::ALLONES_ADDRESS, zoneRadius - 1);
    
    // Reschedule the timer
    scheduleAfter(IARP_updateInterval, IARP_updateTimer);
}

void Zrp::handleIARPUpdate(const Ptr<inet::zrp::IARP_LinkStateUpdate>& update, const L3Address& sourceAddr)
{
    L3Address originatorAddr = update->getSourceAddr();
    unsigned int seqNum = update->getSeqNum();
    
    EV_INFO << "Received IARP Link State Update from " << sourceAddr 
            << " originated by " << originatorAddr
            << " (seq: " << seqNum << ", TTL: " << (int)update->getTTL() << ")" << endl;
    
    // Ignore our own updates
    if (originatorAddr == getSelfIPAddress()) {
        EV_DETAIL << "Ignoring own IARP update" << endl;
        return;
    }
    
    // Check if we already have a newer or equal sequence number from this source
    auto it = linkStateTable.find(originatorAddr);
    if (it != linkStateTable.end()) {
        if (!seqNumIsNewer(seqNum, it->second.seqNum)) {
            EV_DETAIL << "Ignoring stale IARP update (have seq " << it->second.seqNum 
                      << ", received " << seqNum << ")" << endl;
            return;
        }
    }
    
    // Extract data and add/update link state table
    LinkStateEntry entry;
    entry.sourceAddr = originatorAddr;
    entry.zoneRadius = update->getRadius();
    entry.seqNum = seqNum;
    entry.insertTime = simTime();
    
    // Extract link destinations
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
        // Create a copy with decremented TTL for rebroadcast
        auto fwdUpdate = update->dupShared();
        auto mutableUpdate = CHK(dynamicPtrCast<inet::zrp::IARP_LinkStateUpdate>(fwdUpdate));
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
            EV_INFO << "Removing stale link state entry for " << it->first 
                    << " (age: " << (now - it->second.insertTime) << ")" << endl;
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

IRoute *Zrp::IARP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops)
{
    // Create route
    IRoute *newRoute = routingTable->createRoute();

    //Add fields
    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32);  // Host route
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);  // Using MANET as ZRP has no source type in OMNeT++
    newRoute->setSource(this);

    // Attach ZrpRouteData to identify this as an IARP route
    ZrpRouteData *routeData = new ZrpRouteData(ZRP_ROUTE_IARP);
    routeData->setDiscoveryTime(simTime());
    newRoute->setProtocolData(routeData);

    NetworkInterface *ifEntry = interfaceTable->findInterfaceByName(par("interface"));
    if (ifEntry){
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
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto *routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
            if (!routeData || routeData->isIarpRoute()) {
                EV_DETAIL << "Purging IARP route to " << route->getDestinationAsGeneric() << endl;
                routingTable->deleteRoute(route);
            }
        }
    }
}

void Zrp::IARP_computeRoutes()
{
    // Dijkstra's algorithm to compute shortest paths to all nodes within zone
    // Routes are created when a node is visited
    
    L3Address self = getSelfIPAddress();
    
    // Distance from self to each node
    std::map<L3Address, unsigned int> dist;
    
    // Next hop to reach each node (the first hop neighbor)
    std::map<L3Address, L3Address> nextHop;
    
    // Set of nodes whose shortest path has been finalized
    std::set<L3Address> visited;
    
    // Priority queue: (distance, node) - min-heap by distance
    // std::greater makes it a min-heap (smallest distance first)
    typedef std::pair<unsigned int, L3Address> PQEntry;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> pq;
    
    // Initialize: distance to self is 0
    dist[self] = 0;
    pq.push({0, self});
        
    while (!pq.empty()) {
        // Get node with minimum distance
        auto [d, u] = pq.top();
        pq.pop();
        
        // Skip if already visited (we may have duplicate entries in PQ)
        if (visited.count(u)) {
            continue;
        }
        visited.insert(u);
        
        EV_DETAIL << "Dijkstra: processing node " << u << " at distance " << d << endl;
        
        // Create route for this node (except for self)
        if (u != self) {
            IARP_createRoute(u, nextHop[u], d);
        }
        
        // Get neighbors of u
        // For self: use neighborTable (our direct neighbors)
        // For other nodes: use linkStateTable (their advertised neighbors)
        std::vector<std::pair<L3Address, unsigned int>> neighbors;
        
        if (u == self) {
            // Our own neighbors from NDP
            for (const auto& entry : neighborTable) {
                neighbors.push_back({entry.first, 1});  // hop count = 1 for direct neighbors
            }
        }
        else {
            // Neighbors of node u from its link state advertisement
            auto it = linkStateTable.find(u);
            if (it != linkStateTable.end()) {
                for (const auto& linkDest : it->second.linkDestinations) {
                    // Use first metric (hop count)
                    neighbors.push_back({linkDest.destAddr, linkDest.metrics[0]});
                }
            }
        }
        
        // Relax edges to neighbors
        for (const auto& [v, weight] : neighbors) {
            // Skip already visited nodes
            if (visited.count(v)) {
                continue;
            }
            
            unsigned int newDist = d + weight;
            
            // Only consider nodes within zone radius
            if (newDist > zoneRadius) {
                continue;
            }
            
            // Check if this is a shorter path
            if (dist.find(v) == dist.end() || newDist < dist[v]) {
                dist[v] = newDist;
                
                // Set next hop:
                // - If u is self, next hop is v itself (direct neighbor)
                // - Otherwise, inherit next hop from u
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

void Zrp::IARP_updateRoutingTable()
{
    EV_INFO << "Updating IARP routing table..." << endl;
    
    IARP_purgeRoutingTable();
    
    IARP_computeRoutes();
}

// ============================================================================
// IERP Functions
// ============================================================================

void Zrp::IERP_initiateRouteDiscovery(const L3Address& dest)
{
    // RFC IERP Section 5.E.2: Initiate_Route_Discovery(dest)
    EV_INFO << "Initiating IERP route discovery for " << dest << endl;

    auto request = IERP_createRouteRequest(dest);

    // Record this query so we recognize replies and don't loop
    IerpQueryId qid;
    qid.source = getSelfIPAddress();
    qid.queryId = request->getQueryID();
    IERP_recordQuery(qid, dest);

    // Per RFC IERP Section 4: "broadcast() should be replaced with bordercast()"
    // Call BRP to bordercast the route request
    BRP_bordercast(request, -1);  // -1 = new query (no existing BRP cache)
}

const Ptr<inet::zrp::IERP_RouteData> Zrp::IERP_createRouteRequest(const L3Address& dest)
{
    // RFC IERP Section 5.E.2: Build ROUTE_REQUEST packet
    auto request = makeShared<inet::zrp::IERP_RouteData>();

    request->setType(inet::zrp::IERP_QUERY);
    request->setNodePtr(0);     // Points to current position in route (starts at 0)
    request->setQueryID(IERP_queryId++);
    request->setSourceAddr(getSelfIPAddress());
    request->setDestAddr(dest);
    request->setIntermediateNodesArraySize(0);  // No intermediate nodes yet

    // Length: type(1) + length(1) + nodePtr(1) + reserved(1) + queryID(2) + reserved(2) +
    //         sourceAddr(4) + destAddr(4) = 16 bytes base
    request->setLength(4);  // 16 bytes / 4 = 4 words
    request->setChunkLength(B(16));

    EV_DETAIL << "Created IERP ROUTE_REQUEST: src=" << getSelfIPAddress()
              << ", dest=" << dest << ", queryID=" << request->getQueryID() << endl;

    return request;
}

const Ptr<inet::zrp::IERP_RouteData> Zrp::IERP_createRouteReply(const Ptr<inet::zrp::IERP_RouteData>& request)
{
    // RFC IERP Section 5.E.3: Copy ROUTE_REQUEST to ROUTE_REPLY
    // The route accumulated in the request is the path from source to here.
    // We also append any known route to the destination from our IERP/IARP tables.

    auto reply = makeShared<inet::zrp::IERP_RouteData>();

    reply->setType(inet::zrp::IERP_REPLY);
    reply->setQueryID(request->getQueryID());
    reply->setSourceAddr(request->getSourceAddr());
    reply->setDestAddr(request->getDestAddr());

    // Copy the accumulated intermediate nodes from the request
    size_t reqIntermediateCount = request->getIntermediateNodesArraySize();
    reply->setIntermediateNodesArraySize(reqIntermediateCount);
    for (size_t i = 0; i < reqIntermediateCount; i++) {
        reply->setIntermediateNodes(i, request->getIntermediateNodes(i));
    }

    // Node pointer: points to current node in the route (for reversing the reply)
    // In the reply, the pointer starts at the end and moves toward the source
    reply->setNodePtr(reqIntermediateCount);  // We are at the end of the accumulated route

    // Calculate length
    size_t totalNodes = reqIntermediateCount;
    uint8_t lengthInWords = (16 + totalNodes * 4) / 4;
    reply->setLength(lengthInWords);
    reply->setChunkLength(B(16 + totalNodes * 4));

    EV_DETAIL << "Created IERP ROUTE_REPLY: src=" << reply->getSourceAddr()
              << ", dest=" << reply->getDestAddr()
              << ", queryID=" << reply->getQueryID()
              << ", route length=" << totalNodes << " intermediates" << endl;

    return reply;
}

void Zrp::IERP_handleRouteRequest(const Ptr<inet::zrp::IERP_RouteData>& request, const L3Address& sourceAddr)
{
    // RFC IERP Section 5.E.3: Deliver(packet, BRP_cache_ID) - case ROUTE_REQUEST
    L3Address self = getSelfIPAddress();
    L3Address querySource = request->getSourceAddr();
    L3Address queryDest = request->getDestAddr();
    uint16_t queryID = request->getQueryID();

    EV_INFO << "IERP: Received ROUTE_REQUEST from " << sourceAddr
            << " (query src=" << querySource << ", dest=" << queryDest
            << ", queryID=" << queryID << ")" << endl;

    // Ignore requests we originated
    if (querySource == self) {
        EV_DETAIL << "IERP: Ignoring our own route request" << endl;
        return;
    }

    // Check for duplicate queries (loop detection via source route inspection)
    IerpQueryId qid;
    qid.source = querySource;
    qid.queryId = queryID;

    if (IERP_isQuerySeen(qid)) {
        EV_DETAIL << "IERP: Ignoring duplicate route request (already seen queryID="
                  << queryID << " from " << querySource << ")" << endl;
        return;
    }

    // Also check if our address appears in the accumulated route (loop in source route)
    for (size_t i = 0; i < request->getIntermediateNodesArraySize(); i++) {
        if (request->getIntermediateNodes(i) == self) {
            EV_DETAIL << "IERP: Loop detected, our address already in route" << endl;
            return;
        }
    }

    // Record this query
    IERP_recordQuery(qid, queryDest);

    // Record the route from source as a route in our table
    // (the accumulated route gives us a route back to the query source)
    // RFC IERP Section 5.D.2/D.3: "recorded in X's Routing Table"
    {
        std::vector<L3Address> routeToSource;
        routeToSource.push_back(self);  // Start from us
        // Walk the intermediate nodes in reverse to build route to source
        for (int i = (int)request->getIntermediateNodesArraySize() - 1; i >= 0; i--) {
            routeToSource.push_back(request->getIntermediateNodes(i));
        }
        routeToSource.push_back(querySource);

        // Install route to query source if we don't already have one
        if (!IERP_hasRouteToDestination(querySource)) {
            // Next hop is the last intermediate node (or the source if no intermediates)
            L3Address nextHop = routeToSource.size() > 1 ? routeToSource[1] : querySource;
            IERP_createRoute(querySource, nextHop, routeToSource.size() - 1, routeToSource);
        }
    }

    // Check if destination is in our routing zone or we have an IERP route
    // RFC IERP Section 5.D.2: "destination appears within X's routing zone"
    bool haveRouteToQuery = false;
    IRoute *routeToDest = nullptr;

    // First check IARP routes (destination in routing zone)
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == queryDest) {
            haveRouteToQuery = true;
            routeToDest = route;
            break;
        }
    }

    // Are we the destination ourselves?
    if (queryDest == self) {
        haveRouteToQuery = true;
    }

    if (haveRouteToQuery) {
        // RFC IERP Section 5.E.3 case ROUTE_REQUEST:
        // "Append discovered route to accumulated route and send reply back to the source"
        EV_INFO << "IERP: Found route to destination " << queryDest
                << ", sending ROUTE_REPLY" << endl;

        // Append our address to the route before creating reply
        auto mutableRequest = request->dupShared();
        auto editableRequest = CHK(dynamicPtrCast<inet::zrp::IERP_RouteData>(mutableRequest));

        // Add our address to intermediate nodes
        size_t currentSize = editableRequest->getIntermediateNodesArraySize();
        editableRequest->setIntermediateNodesArraySize(currentSize + 1);
        editableRequest->setIntermediateNodes(currentSize, self);
        editableRequest->setNodePtr(currentSize + 1);

        // If destination is not us, and we have an IARP route, append the route
        // through our zone to the destination
        if (queryDest != self && routeToDest) {
            auto *routeData = dynamic_cast<ZrpRouteData*>(routeToDest->getProtocolData());
            if (routeData && routeData->isIerpRoute() && !routeData->getSourceRoute().empty()) {
                // Append IERP route's intermediate nodes (skip first which is us)
                const auto& srcRoute = routeData->getSourceRoute();
                for (size_t i = 1; i < srcRoute.size() - 1; i++) {
                    size_t sz = editableRequest->getIntermediateNodesArraySize();
                    editableRequest->setIntermediateNodesArraySize(sz + 1);
                    editableRequest->setIntermediateNodes(sz, srcRoute[i]);
                }
            }
            // If it's an IARP route, the destination is within our zone.
            // The IARP route gives us next-hop, but for source routing
            // we need to record the path through the zone.
            // For simplicity: just record our address. The destination
            // is reachable from us within the zone.
        }

        // Create and send reply
        auto reply = IERP_createRouteReply(editableRequest);

        // Send reply back toward source along the reverse accumulated route.
        // The next hop toward the source is the last intermediate node before us.
        L3Address nextHopToSource;
        if (editableRequest->getIntermediateNodesArraySize() >= 2) {
            // The node just before us in the route
            nextHopToSource = editableRequest->getIntermediateNodes(
                editableRequest->getIntermediateNodesArraySize() - 2);
        } else {
            // We are the first hop from source, reply directly
            nextHopToSource = querySource;
        }

        // Send via IP directly (not bordercast) per RFC
        sendZrpPacket(reply, nextHopToSource, 255);
    }
    else {
        // RFC IERP Section 5.E.3 case ROUTE_REQUEST (no route):
        // "append MY_ID to accumulated route and continue to forward ROUTE_REQUEST"
        EV_INFO << "IERP: No route to " << queryDest << ", forwarding ROUTE_REQUEST" << endl;

        auto mutableRequest = request->dupShared();
        auto editableRequest = CHK(dynamicPtrCast<inet::zrp::IERP_RouteData>(mutableRequest));

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

        // Per RFC: "bordercast(packet, BRP_cache_ID)" replaces broadcast()
        BRP_bordercast(editableRequest, 0);  // 0 = existing query being relayed
    }
}

void Zrp::IERP_handleRouteReply(const Ptr<inet::zrp::IERP_RouteData>& reply, const L3Address& sourceAddr)
{
    // RFC IERP Section 5.E.3: Deliver(packet) - case ROUTE_REPLY
    L3Address self = getSelfIPAddress();
    L3Address routeSource = reply->getSourceAddr();
    L3Address routeDest = reply->getDestAddr();
    uint16_t queryID = reply->getQueryID();

    EV_INFO << "IERP: Received ROUTE_REPLY from " << sourceAddr
            << " (route src=" << routeSource << ", dest=" << routeDest
            << ", queryID=" << queryID << ")" << endl;

    // RFC: "Extract route from packet and record it in the IERP Routing Table"
    // Build full route: source -> intermediate nodes -> destination
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

    // RFC: "route_tail = route(current_hop_ptr : length(route))"
    // Record route toward the destination from our position
    std::vector<L3Address> routeToDest;
    for (size_t i = myPos; i < fullRoute.size(); i++) {
        routeToDest.push_back(fullRoute[i]);
    }

    // Install/update route to destination
    if (routeToDest.size() > 1) {
        L3Address nextHop = routeToDest[1];
        unsigned int hops = routeToDest.size() - 1;

        // Remove existing IERP route to this destination if any
        IRoute *existingRoute = IERP_findRoute(routeDest);
        if (existingRoute) {
            routingTable->deleteRoute(existingRoute);
        }

        IERP_createRoute(routeDest, nextHop, hops, routeToDest);

        EV_INFO << "IERP: Installed route to " << routeDest << " via " << nextHop
                << " (" << hops << " hops, full route: ";
        for (size_t i = 0; i < routeToDest.size(); i++) {
            if (i > 0) EV_INFO << "->";
            EV_INFO << routeToDest[i];
        }
        EV_INFO << ")" << endl;
    }

    // RFC: "Forward ROUTE_REPLY until it reaches source"
    if (self != routeSource) {
        // Decrement node pointer and forward to previous hop (toward source)
        auto fwdReply = reply->dupShared();
        auto editableReply = CHK(dynamicPtrCast<inet::zrp::IERP_RouteData>(fwdReply));

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

        // Send directly via IP (not bordercast) per RFC
        sendZrpPacket(editableReply, nextHopToSource, 255);
    }
    else {
        EV_INFO << "IERP: ROUTE_REPLY reached query source. Route discovery complete for "
                << routeDest << endl;
        // Release any datagrams we buffered while waiting for this route
        IERP_completeRouteDiscovery(routeDest);
    }
}

void Zrp::IERP_routeMaintenance()
{
    // RFC IERP Section 5.E.1: IARP_updated()
    // "For each dest in IERP_Routing_Table, for each route:
    //    for j = 1:L, lookup IARP path to each node in route.
    //    Update the IERP route using the IARP path that minimizes
    //    the distance to the IERP route's destination."
    //
    // In our implementation, IERP routes are stored in the routing table
    // with ZrpRouteData::isIerpRoute(). We iterate over them and try to
    // shorten each using current IARP topology knowledge.

    L3Address self = getSelfIPAddress();

    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() != this) continue;

        auto *routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
        if (!routeData || !routeData->isIerpRoute()) continue;

        const std::vector<L3Address>& sourceRoute = routeData->getSourceRoute();
        if (sourceRoute.size() < 2) continue;

        L3Address dest = route->getDestinationAsGeneric();

        // Try to shorten the route by finding IARP paths to downstream nodes
        // RFC pseudocode: for j = 1:L, find the IARP path that gives minimum
        // total route length to destination.
        unsigned int minDist = sourceRoute.size() - 1;  // current hop count
        std::vector<L3Address> bestRoute = sourceRoute;
        bool improved = false;

        for (size_t j = 1; j < sourceRoute.size(); j++) {
            L3Address intermediateNode = sourceRoute[j];

            // Check if we have an IARP route to this intermediate node
            IRoute *iarpRoute = nullptr;
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute *candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this &&
                    candidate->getDestinationAsGeneric() == intermediateNode) {
                    auto *candData = dynamic_cast<ZrpRouteData*>(candidate->getProtocolData());
                    if (candData && candData->isIarpRoute()) {
                        iarpRoute = candidate;
                        break;
                    }
                }
            }

            if (iarpRoute) {
                // We can reach intermediateNode via IARP (it's in our zone).
                // New route = IARP path to intermediateNode + rest of source route from j onward
                unsigned int iarpHops = iarpRoute->getMetric();
                unsigned int tailHops = sourceRoute.size() - 1 - j;
                unsigned int totalHops = iarpHops + tailHops;

                if (totalHops < minDist) {
                    minDist = totalHops;

                    // Build new route: us -> (IARP next hop to intermediateNode) ... intermediateNode -> rest
                    // For simplicity, we update the next hop and metric.
                    // The full source route from intermediateNode onward stays the same.
                    bestRoute.clear();
                    bestRoute.push_back(self);
                    // We don't have the full IARP path stored (just next hop + metric),
                    // so we record a simplified route through the zone.
                    // The actual forwarding will use IARP's hop-by-hop routing within the zone.
                    for (size_t k = j; k < sourceRoute.size(); k++) {
                        bestRoute.push_back(sourceRoute[k]);
                    }

                    improved = true;
                }
            }
        }

        if (improved) {
            EV_INFO << "IERP: Route maintenance shortened route to " << dest
                    << " from " << (sourceRoute.size() - 1) << " to " << minDist << " hops" << endl;

            // Update the route in the routing table
            route->setNextHop(bestRoute.size() > 1 ? bestRoute[1] : dest);
            route->setMetric(minDist);
            routeData->setSourceRoute(bestRoute);
        }

        // Check if route is still valid (next hop should be reachable via IARP or be a neighbor)
        L3Address nextHop = route->getNextHopAsGeneric();
        bool nextHopReachable = false;

        // Check if next hop is a direct neighbor
        if (neighborTable.find(nextHop) != neighborTable.end()) {
            nextHopReachable = true;
        }
        // Or reachable via IARP
        else {
            for (int r = 0; r < routingTable->getNumRoutes(); r++) {
                IRoute *candidate = routingTable->getRoute(r);
                if (candidate->getSource() == this &&
                    candidate->getDestinationAsGeneric() == nextHop) {
                    auto *candData = dynamic_cast<ZrpRouteData*>(candidate->getProtocolData());
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

IRoute *Zrp::IERP_createRoute(const L3Address& dest, const L3Address& nextHop, unsigned int hops,
                               const std::vector<L3Address>& fullRoute)
{
    IRoute *newRoute = routingTable->createRoute();

    newRoute->setDestination(dest);
    newRoute->setPrefixLength(32);
    newRoute->setNextHop(nextHop);
    newRoute->setMetric(hops);
    newRoute->setSourceType(IRoute::MANET);
    newRoute->setSource(this);

    // Attach ZrpRouteData with IERP type and full source route
    ZrpRouteData *routeData = new ZrpRouteData(ZRP_ROUTE_IERP);
    routeData->setSourceRoute(fullRoute);
    routeData->setDiscoveryTime(simTime());
    newRoute->setProtocolData(routeData);

    NetworkInterface *ifEntry = interfaceTable->findInterfaceByName(par("interface"));
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
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            auto *routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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

IRoute *Zrp::IERP_findRoute(const L3Address& dest) const
{
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this && route->getDestinationAsGeneric() == dest) {
            auto *routeData = dynamic_cast<ZrpRouteData*>(route->getProtocolData());
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

void Zrp::IERP_delayDatagram(Packet *datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& dest = networkHeader->getDestinationAddress();
    EV_DETAIL << "Buffering datagram for destination " << dest << endl;
    delayedPackets.insert(std::pair<L3Address, Packet *>(dest, datagram));
}

void Zrp::IERP_completeRouteDiscovery(const L3Address& dest)
{
    EV_DETAIL << "Completing route discovery for " << dest
              << ", releasing " << delayedPackets.count(dest) << " buffered datagrams" << endl;

    auto lt = delayedPackets.lower_bound(dest);
    auto ut = delayedPackets.upper_bound(dest);

    // Reinject the delayed datagrams now that a route exists
    for (auto it = lt; it != ut; it++) {
        Packet *datagram = it->second;
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
    // Remove query records older than a reasonable timeout
    // This prevents the table from growing indefinitely
    simtime_t now = simTime();
    simtime_t queryLifetime = 120;  // Queries older than 2 minutes are safe to forget

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

// ============================================================================
// BRP Stub Functions
// ============================================================================

void Zrp::BRP_bordercast(const Ptr<inet::zrp::IERP_RouteData>& packet, int brpCacheId)
{
    // STUB: Full BRP implementation will construct bordercast trees,
    // apply coverage tracking, and use jitter delays.
    //
    // For now: degenerate to simple broadcast (zone radius 1 = flood search).
    // Per RFC IERP Section 2: "For a routing zone radius of one hop,
    // bordercasting degenerates into flood searching."
    //
    // When BRP is implemented, this will:
    // 1. Construct a bordercast tree spanning uncovered peripheral nodes
    // 2. Forward the query to tree neighbors with random jitter delay
    //    (using schedulePendingTimer with ZRP_SELF_BRP_JITTER kind)
    // 3. Mark routing zone nodes as covered after forwarding

    EV_INFO << "BRP_bordercast (STUB): Broadcasting IERP packet as simple flood" << endl;

    sendZrpPacket(packet, Ipv4Address::ALLONES_ADDRESS, zoneRadius);
}

// ============================================================================
// Pending Timer Management
// ============================================================================

void Zrp::schedulePendingTimer(cMessage *msg, simtime_t delay)
{
    pendingTimers.push_back(msg);
    scheduleAfter(delay, msg);
}

void Zrp::cancelPendingTimer(cMessage *msg)
{
    auto it = std::find(pendingTimers.begin(), pendingTimers.end(), msg);
    if (it != pendingTimers.end()) {
        pendingTimers.erase(it);
    }
    cancelAndDelete(msg);
}

void Zrp::cancelAllPendingTimers()
{
    for (auto *msg : pendingTimers) {
        cancelAndDelete(msg);
    }
    pendingTimers.clear();
}


} // namespace zrp


