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
	    double IARP_updateInterval @unit(s) = default(1s); // Interval between IARP updates
	    double linkStateLifetime @unit(s) = default(3s);  // How long before link state entries expire
	    double debugInterval @unit(s) = default(0s);      // Debug output interval (0 = disabled)
	    double brpJitterMax @unit(s) = default(0.1s);     // Max random jitter before BRP relays query to IERP 
	    double brpCoverageLifetime @unit(s) = default(30s); // How long to keep BRP query coverage entries 
	    double ierpRetryInterval @unit(s) = default(3s);    // Interval between IERP route request retries
	    int ierpMaxRetries = default(3);                    // Max number of IERP route request retries before dropping packets
	
	gates:
	    input socketIn;
	    output socketOut;
}