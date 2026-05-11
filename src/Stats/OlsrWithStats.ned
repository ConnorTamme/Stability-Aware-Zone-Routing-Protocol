//
// Statistics-instrumented OLSR. Extends the vendor inetmanet Olsr module,
// adding the controlPacketSent signal/statistic so routing overhead can be
// compared against ZRP, SAZRP, and AODV. OLSR has no route discovery, so no
// routeDiscoveryStarted signal is declared.
//

package sa_zrp.Stats;

import inet.routing.extras.Olsr;


simple OlsrWithStats extends Olsr
{
    parameters:
        @class("inet::inetmanet::OlsrWithStats");

        @signal[controlPacketSent](type=inet::Packet);
        @statistic[controlPacketSent](title="control packets sent"; source=controlPacketSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
}
