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
        IARP_helloTimer = new cMessage("IARP_helloTimer");

        zrpUDPPort = par("udpPort");
        NDP_helloInterval = par("NDP_helloInterval");
        IARP_helloInterval = par("IARP_helloInterval");
        zoneRadius = par("zoneRadius");

    }
}

//Receiving cMessages
void Zrp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == NDP_helloTimer) {
            sendNDPHello();
        }
        else if (msg == IARP_helloTimer) {
            // TODO: Send IARP updates
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

    scheduleAfter(NDP_helloInterval,NDP_helloTimer);
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
    cancelAndDelete(IARP_helloTimer);
    IARP_helloTimer = nullptr;
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
    
    // Try to cast to NDP_Hello
    if (auto ndpHello = dynamicPtrCast<const inet::zrp::NDP_Hello>(chunk)) {
        handleNDPHello(CHK(dynamicPtrCast<inet::zrp::NDP_Hello>(chunk->dupShared())), sourceAddr);
    }
    else if (auto iarpHello = dynamicPtrCast<const inet::zrp::IARP_LinkStateUpdate>(chunk)) {
        // Handle IARP Link State Update
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

} // namespace zrp


