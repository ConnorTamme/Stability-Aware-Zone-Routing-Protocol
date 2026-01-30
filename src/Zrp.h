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

// Must be defined before including ZrpControlPackets_m.h
#define IARP_METRIC_COUNT 1

#include "inet/common/ModuleRefByPar.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "ZrpControlPackets_m.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"



//As the RFC assumes a 32 bit address only IPv4 is to be supported

using namespace inet;

namespace zrp {

// Link destination info for the link state table
struct LinkDestInfo {
    L3Address destAddr;
    uint16_t metrics[IARP_METRIC_COUNT];  // metric values (e.g., hop count)
};

// Link state table entry - stores link state info from a source node
struct LinkStateEntry {
    L3Address sourceAddr;           // Node that originated this link state
    unsigned int zoneRadius;        // Zone radius of the source node
    unsigned int seqNum;            // Link state sequence number
    simtime_t insertTime;           // When this entry was inserted/updated
    std::vector<LinkDestInfo> linkDestinations;  // List of neighbors and their metrics
};

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

    // state
    unsigned int NDP_seqNum = 0;  // sequence number for NDP hello messages
    unsigned int IARP_seqNum = 0; // sequence number for IARP link state updates
    std::map<L3Address, simtime_t> neighborTable;  // neighbor address -> last heard time
    std::map<L3Address, LinkStateEntry> linkStateTable;  // source address -> link state entry

    // self messages
    cMessage *NDP_helloTimer = nullptr;
    cMessage *IARP_updateTimer = nullptr;

  protected:
    void handleMessageWhenUp(cMessage *msg) override;
    void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

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
    void clearState();
    void processPacket(Packet *packet);
    void sendZrpPacket(const Ptr<FieldsChunk>& payload, const L3Address& destAddr, unsigned int ttl);

    // NDP Functions
    const Ptr<inet::zrp::NDP_Hello> createNDPHello();
    void sendNDPHello();
    void handleNDPHello(const Ptr<inet::zrp::NDP_Hello>& hello, const L3Address& sourceAddr);

    //IARP Functions
    const Ptr<inet::zrp::IARP_LinkStateUpdate> createIARPUpdate();
    void sendIARPUpdate();
    void handleIARPUpdate(const Ptr<inet::zrp::IARP_LinkStateUpdate>& update, const L3Address& sourceAddr);
    void IARP_refreshLinkStateTable();
    void IARP_updateRoutingTable();  // TODO: Implement route computation

  public:
    Zrp();
    virtual ~Zrp();
};

} // namespace zrp



#endif //ZRP_H_
