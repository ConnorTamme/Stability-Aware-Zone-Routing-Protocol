//
// Statistics-instrumented AODV. Extends the vendor Aodv module without
// changing its behaviour; adds controlPacketSent and routeDiscoveryStarted
// signals/statistics so routing overhead and route-rediscovery rates can be
// compared against ZRP, SAZRP, and OLSR on a common footing.
//

package sa_zrp.Stats;

import inet.routing.aodv.Aodv;


simple AodvWithStats extends Aodv
{
    parameters:
        @class("inet::aodv::AodvWithStats");

        @signal[controlPacketSent](type=inet::Packet);
        @statistic[controlPacketSent](title="control packets sent"; source=controlPacketSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @signal[routeDiscoveryStarted];
        @statistic[routeDiscoveryStarted](title="route discoveries initiated"; source=routeDiscoveryStarted; record=count,vector; interpolationmode=none);
}
