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

namespace inet{
namespace zrp{

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
        addressType = getSelfIPAddress().getAddressType();
    }

    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Get containing host module
        host = getContainingNode(this);

        // Reference routing table and interface table
        routingTable.reference(this, "routingTableModule", true);
        interfaceTable.reference(this, "interfaceTableModule", true);
        networkProtocol.reference(this, "networkProtocolModule", true);

        // Add parameters and setup here
        NDP_helloTimer = new cMessage("NDP_helloTimer");
        IARP_helloTimer = new cMessage("IARP_helloTimer");
    }
}

//Receiving cMessages
void Zrp:: handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()){
        return;
    }
    else{
        return;
    }
}

void Zrp::handleStartOperation(LifecycleOperation *operation)
{
    // TODO: Initialize routing protocol, register hooks, open UDP socket
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

/* Netfilter hooks */
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
    // TODO: Process incoming ZRP control packets
    delete packet;
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

/* cListener */
void Zrp::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method("receiveSignal");
    // TODO: Handle link breakage signals
}

/* Helper functions */
L3Address Zrp::getSelfIPAddress() const
{
    return routingTable->getRouterIdAsGeneric();
}

} // namespace zrp
} // namespace inet


