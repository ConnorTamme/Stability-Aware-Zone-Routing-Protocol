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

package sa_zrp;

import inet.applications.contract.IApp;

simple Zrp like IApp
{
	parameters:
	    @class("zrp::Zrp");
	    //All stuff straight from Aodv.ned
	    string routingTableModule = default("^.ipv4.routingTable");
	    string interfaceTableModule = default("^.interfaceTable");
	    string networkProtocolModule = default("^.ipv4.ip");
	    int udpPort = default(654);
	    string interface = default("wlan0");
	
	    int zoneRadius= default(2);
	    double NDP_helloInterval @unit(s) = default(1s);
	    double IARP_updateInterval @unit(s) = default(1s);
	    double linkStateLifetime @unit(s) = default(3s);  // How long before link state entries expire
	    double debugInterval @unit(s) = default(0s);      // Debug output interval (0 = disabled)
	    double brpJitterMax @unit(s) = default(0.1s);     // Max random jitter before BRP relays query to IERP (RFC BRP Section 4: RELAY_JITTER)
	    double brpCoverageLifetime @unit(s) = default(30s); // How long to keep BRP query coverage entries (RFC: MAX_QUERY_LIFETIME)
	
	gates:
	    input socketIn;
	    output socketOut;
}