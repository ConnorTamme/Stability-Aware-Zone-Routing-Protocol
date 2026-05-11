//
// OLSR statistics subclass. OLSR assembles each outgoing UDP datagram from a
// drained queue of up-to-OLSR_MAX_MSGS messages, with one Packet per batch.
// The Packet is local to Olsr::send_pkt(), so we peek at the queue before
// delegating to the parent: for each batch we compute the byte length that
// send_pkt() is about to emit, build an ephemeral marker Packet with that
// length, and emit controlPacketSent so sum(packetBytes) records the real
// serialized size. The parent then performs the actual sends unchanged.
//

#include "OlsrWithStats.h"

#include "inet/common/Units.h"
#include "inet/common/packet/Packet.h"
#include "inet/routing/extras/olsr/OlsrMsg.h"
#include "inet/routing/extras/olsr/OlrsPkt_m.h"

namespace inet {
namespace inetmanet {

Define_Module(OlsrWithStats);

simsignal_t OlsrWithStats::controlPacketSentSignal = registerSignal("controlPacketSent");

void OlsrWithStats::send_pkt()
{
    int num_msgs = (int)msgs_.size();
    if (num_msgs == 0) {
        Olsr::send_pkt();
        return;
    }

    int num_pkts = (num_msgs % OLSR_MAX_MSGS == 0)
                       ? num_msgs / OLSR_MAX_MSGS
                       : (num_msgs / OLSR_MAX_MSGS + 1);

    auto it = msgs_.begin();
    for (int p = 0; p < num_pkts; p++) {
        B pktBytes = B(OLSR_PKT_HDR_SIZE);
        int j = 0;
        auto batchEnd = it;
        while (batchEnd != msgs_.end() && j < OLSR_MAX_MSGS) {
            pktBytes += B((*batchEnd).size());
            ++batchEnd;
            ++j;
        }

        auto op = makeShared<OlsrPkt>();
        op->setChunkLength(pktBytes);
        Packet* markerPkt = new Packet("OLSR Pkt", op);
        emit(controlPacketSentSignal, markerPkt);
        delete markerPkt;

        it = batchEnd;
    }

    Olsr::send_pkt();
}

} // namespace inetmanet
} // namespace inet
