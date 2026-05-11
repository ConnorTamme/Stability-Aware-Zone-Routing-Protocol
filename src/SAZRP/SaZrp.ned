//
// Defines a SAZRP module so a node can use Stability-Aware ZRP
//

package sa_zrp.SAZRP;

import inet.applications.contract.IApp;

simple SaZrp like IApp
{
	parameters:
	    @class("inet::sazrp::SaZrp");
	    //All stuff straight from Aodv.ned
	    string routingTableModule = default("^.ipv4.routingTable");
	    string interfaceTableModule = default("^.interfaceTable");
	    string networkProtocolModule = default("^.ipv4.ip");
	    int udpPort = default(654);
	    string interface = default("wlan0");

		//Parameters
	    double stabilityThreshold = default(0.3); // Path stability threshold tau for zone membership
	    double commsRange @unit(m);               // Transmission range R in metres (required, scenario dependent)
	    double vMax @unit(mps);                   // Maximum UAV speed in m/s (required, scenario dependent)
	    double emaAlpha = default(0.3);           // EMA smoothing factor for per-link stability
	    double distanceExponent = default(4);     // Exponent p in D = 1 - (d/R)^p
	    double decayBeta = default(0.7);          // Per-hop multiplicative decay applied to running stability
	    double NDP_helloInterval @unit(s) = default(1s); // Interval between NDP hello messages
	    double IARP_updateInterval @unit(s) = default(1s); // Interval between IARP updates
	    double linkStateLifetime @unit(s) = default(3s);  // How long before link state entries expire
	    double debugInterval @unit(s) = default(0s);      // Debug output interval (0 = disabled)
	    double brpJitterMax @unit(s) = default(0.1s);     // Max random jitter before BRP relays query to IERP
	    double brpCoverageLifetime @unit(s) = default(30s); // How long to keep BRP query coverage entries
	    double ierpRetryInterval @unit(s) = default(3s);    // Interval between IERP route request retries
	    int ierpMaxRetries = default(3);                    // Max number of IERP route request retries before dropping packets
	    double delayedPacketLifetime @unit(s) = default(5s); // Max age of a queued datagram waiting for route discovery; older packets are dropped instead of reinjected

	    @signal[controlPacketSent](type=inet::Packet);
	    @statistic[controlPacketSent](title="control packets sent"; source=controlPacketSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
	    @signal[routeDiscoveryStarted];
	    @statistic[routeDiscoveryStarted](title="route discoveries initiated"; source=routeDiscoveryStarted; record=count,vector; interpolationmode=none);

	gates:
	    input socketIn;
	    output socketOut;
}
