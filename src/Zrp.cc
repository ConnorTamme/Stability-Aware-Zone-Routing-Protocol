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

        zrpUDPPort = par("udpPort");
        NDP_helloInterval = par("NDP_helloInterval");
        IARP_updateInterval = par("IARP_updateInterval");
        zoneRadius = par("zoneRadius");
        linkStateLifetime = par("linkStateLifetime");

    }
}

//Receiving cMessages
void Zrp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == NDP_helloTimer) {
            sendNDPHello();
        }
        else if (msg == IARP_updateTimer) {
            IARP_refreshLinkStateTable();
            sendIARPUpdate();
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

    scheduleAfter(NDP_helloInterval, NDP_helloTimer);
    scheduleAfter(IARP_updateInterval, IARP_updateTimer);
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
    // Cancel and delete self messages
    cancelAndDelete(NDP_helloTimer);
    NDP_helloTimer = nullptr;
    cancelAndDelete(IARP_updateTimer);
    IARP_updateTimer = nullptr;
    
    // Clear state tables
    neighborTable.clear();
    linkStateTable.clear();
    
    // Reset sequence numbers
    NDP_seqNum = 0;
    IARP_seqNum = 0;
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
    // TODO: Ensure route exists for locally originated datagrams
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

//Helper functions
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

// IARP Functions
const Ptr<inet::zrp::IARP_LinkStateUpdate> Zrp::createIARPUpdate()
{
    auto update = makeShared<inet::zrp::IARP_LinkStateUpdate>();
    
    // Set packet fields per RFC
    update->setSourceAddr(getSelfIPAddress());
    update->setSeqNum(IARP_seqNum++); // TODO: Potentially an issue when seq nums wrap around
    update->setRadius(zoneRadius);
    update->setTTL(zoneRadius - 1);  // Making TTL equal zoneRadius - 1 really thre me off so I
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
        if (seqNum <= it->second.seqNum) {
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
    
    // TODO: Recompute routing table
    // IARP_updateRoutingTable();
    
    // TODO: Notify IERP of topology change
    
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
    
    // TODO: Update routing table after removing stale entries
    // IARP_updateRoutingTable();
    
    // TODO: Report topology changes to IERP
}

void Zrp::IARP_updateRoutingTable()
{
    // TODO: Implement Dijkstra's algorithm or similar to compute
    // shortest paths to all nodes within the zone based on link state table
    EV_DETAIL << "IARP_updateRoutingTable() not yet implemented" << endl;
}

} // namespace zrp


