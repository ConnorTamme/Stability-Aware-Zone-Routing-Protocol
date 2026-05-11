//
// Thin subclass of INET's AODV that emits the common FANET-experiment
// statistics signals. See AodvWithStats.h for rationale.
//

#include "AodvWithStats.h"

#include "inet/common/packet/Packet.h"

namespace inet {
namespace aodv {

Define_Module(AodvWithStats);

simsignal_t AodvWithStats::controlPacketSentSignal = registerSignal("controlPacketSent");
simsignal_t AodvWithStats::routeDiscoveryStartedSignal = registerSignal("routeDiscoveryStarted");

void AodvWithStats::sendAODVPacket(const Ptr<AodvControlPacket>& aodvPacket,
                                    const L3Address& destAddr,
                                    unsigned int timeToLive,
                                    double delay)
{
    // The parent constructs a fresh Packet wrapping aodvPacket before sending,
    // but that Packet is local to the parent's scope and never observable from
    // here. To keep sum(packetBytes) faithful we build an equivalent marker
    // Packet (same name, same chunk) purely for the signal emission, then
    // delete it immediately. The chunk becomes immutable on first insertion,
    // which is the state the parent's own Packet construction also expects.
    const char* className = aodvPacket->getClassName();
    Packet* markerPkt = new Packet(
        !strncmp("inet::", className, 6) ? className + 6 : className, aodvPacket);
    emit(controlPacketSentSignal, markerPkt);
    delete markerPkt;

    Aodv::sendAODVPacket(aodvPacket, destAddr, timeToLive, delay);
}

void AodvWithStats::startRouteDiscovery(const L3Address& target, unsigned int timeToLive)
{
    emit(routeDiscoveryStartedSignal, (intval_t)1);
    Aodv::startRouteDiscovery(target, timeToLive);
}

} // namespace aodv
} // namespace inet
