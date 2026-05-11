//Connor Tamme, tammeconnor@gmail.com
//
// Defines a ZRP module so a node can use ZRP
//

package sa_zrp;

import inet.applications.contract.IApp;

simple Zrp like IApp
{
	parameters:
	    @class("inet::zrp::Zrp");
	    //All stuff straight from Aodv.ned
	    string routingTableModule = default("^.ipv4.routingTable");
	    string interfaceTableModule = default("^.interfaceTable");
	    string networkProtocolModule = default("^.ipv4.ip");
	    int udpPort = default(654);
	    string interface = default("wlan0");

		//Parameters
	    int zoneRadius= default(2); // Radius of the routing zone in hops
	    double NDP_helloInterval @unit(s) = default(1s); // Interval between NDP hello messages
	    double IARP_updateInterval @unit(s) = default(4s); // Interval between IARP updates
	    double IARP_eventDelay @unit(ms) = default(500ms);  // Delay before sending an event-driven IARP update after neighbour set changes
	    double IARP_eventJitter @unit(ms) = default(15ms);  // Random jitter added on top of IARP_eventDelay
	    double linkStateLifetime @unit(s) = default(8s);  // How long before link state entries expire
	    double debugInterval @unit(s) = default(0s);      // Debug output interval (0 = disabled)
	    double brpJitterMax @unit(s) = default(0.1s);     // Max random jitter before BRP relays query to IERP 
	    double brpCoverageLifetime @unit(s) = default(30s); // How long to keep BRP query coverage entries 
	    double ierpRetryInterval @unit(s) = default(2s);    // Interval between IERP route request retries
	    int ierpMaxRetries = default(3);                    // Max number of IERP route request retries before dropping packets
	    double delayedPacketLifetime @unit(s) = default(8s); // Max age of a queued datagram waiting for route discovery; older packets are dropped instead of reinjected

	    @signal[controlPacketSent](type=inet::Packet);
	    @statistic[controlPacketSent](title="control packets sent"; source=controlPacketSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
	    @signal[routeDiscoveryStarted];
	    @statistic[routeDiscoveryStarted](title="route discoveries initiated (first attempt only)"; source=routeDiscoveryStarted; record=count,vector; interpolationmode=none);
	    @signal[routeDiscoveryRetried];
	    @statistic[routeDiscoveryRetried](title="route discovery retransmissions (driven by ierpRetryInterval)"; source=routeDiscoveryRetried; record=count,vector; interpolationmode=none);

	    // Per-type control packet attribution. record= uses scalar filters (no
	    // histogram) so this side-steps the appendBins crash that caught the
	    // joint StabDecay sweep at high tau. count + sum(packetBytes) gives
	    // total wire footprint per type; mean/min/max/stddev(packetBytes)
	    // characterises the size distribution -- IARP_LinkStateUpdate in
	    // particular grows linearly with neighbour count, so this is where
	    // SA-ZRP's "more strict admission -> larger fan-out" cost shows up.
	    @signal[pktSentNDP](type=inet::Packet);
	    @statistic[pktSentNDP](title="NDP_Hello packets sent"; source=pktSentNDP; record=count,"stats(packetBytes)"; interpolationmode=none);
	    @signal[pktSentIARP](type=inet::Packet);
	    @statistic[pktSentIARP](title="IARP_LinkStateUpdate packets sent"; source=pktSentIARP; record=count,"stats(packetBytes)"; interpolationmode=none);
	    @signal[pktSentIERPQuery](type=inet::Packet);
	    @statistic[pktSentIERPQuery](title="IERP query (route request) packets sent -- includes retransmissions"; source=pktSentIERPQuery; record=count,"stats(packetBytes)"; interpolationmode=none);
	    @signal[pktSentIERPReply](type=inet::Packet);
	    @statistic[pktSentIERPReply](title="IERP reply (route response) packets sent"; source=pktSentIERPReply; record=count,"stats(packetBytes)"; interpolationmode=none);
	    @signal[pktSentBRP](type=inet::Packet);
	    @statistic[pktSentBRP](title="BRP bordercast packets sent (carries an encapsulated IERP query)"; source=pktSentBRP; record=count,"stats(packetBytes)"; interpolationmode=none);

	    // Per-discovery quality metrics (mirror of SaZrp.ned). Fire only at
	    // the IERP query source on the first arriving reply; pool sum/count
	    // across routing modules to get the network-wide average.
	    @signal[routeLength];
	    @statistic[routeLength](title="hop count of newly-discovered IERP routes (at source)"; source=routeLength; record=count,sum,mean,vector; interpolationmode=none);
	    @signal[routeDiscoveryTime];
	    @statistic[routeDiscoveryTime](title="elapsed time from first IERP query to arriving reply (at source)"; source=routeDiscoveryTime; record=count,sum,mean,vector; interpolationmode=none);

	gates:
	    input socketIn;
	    output socketOut;
}