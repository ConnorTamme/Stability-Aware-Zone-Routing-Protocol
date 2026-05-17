//
// Generalised Zone Routing Protocol (GZRP). Compound module that wraps the
// routing-protocol simple module (GzrpProtocol) together with four
// pluggable strategy submodules (scoring, decay, gate, threshold).
//
// All scenario configuration goes on the compound's parameters; the .ini
// also addresses each strategy submodule via **.app[*].scoring.typename
// etc. The compound forwards its parameters down to GzrpProtocol via the
// parent.X syntax so the C++ class sees the same values.
//

package sa_zrp.GZRP;

import inet.applications.contract.IApp;
import sa_zrp.GZRP.Strategies.IScoringStrategy;
import sa_zrp.GZRP.Strategies.IDecayStrategy;
import sa_zrp.GZRP.Strategies.IGateStrategy;
import sa_zrp.GZRP.Strategies.IThresholdStrategy;


module Gzrp like IApp
{
    parameters:
        // These get forwarded down to the inner GzrpProtocol via
        // parent.X, so path resolution happens from the protocol module's
        // location -- one extra ^ is needed to climb out of this compound
        // and reach the host before drilling into ipv4 / interfaceTable.
        string routingTableModule = default("^.^.ipv4.routingTable");
        string interfaceTableModule = default("^.^.interfaceTable");
        string networkProtocolModule = default("^.^.ipv4.ip");
        int udpPort = default(654);
        string interface = default("wlan0");

        // Core knobs preserved from SAZRP. Strategy-specific values
        // (commsRange, vMax, q, betaMin/Max, etc.) live on the strategy
        // submodules below. emaAlpha is the smoothing factor applied at
        // the core between successive scoring->scoreLink samples.
        bool enableOriginatorPreDecay = default(true);
        double emaAlpha = default(0.3);

        // How a fresh ROUTE_REPLY arbitrates against an existing IERP route
        // to the same destination. "last-wins" replicates classic ZRP (every
        // reply replaces the installed route, last-arriving wins). "stability-hops"
        // is the SAZRP/GZRP-Sazrp tiebreak: prefer a high-stability next hop
        // over a low-stability one, otherwise prefer strictly fewer hops,
        // otherwise keep the existing route. GZRP-Classic configs must set
        // "last-wins" for ZRP parity; default keeps SAZRP semantics.
        string ierpReplyInstallPolicy = default("stability-hops");

        double NDP_helloInterval @unit(s) = default(1s);
        double IARP_updateInterval @unit(s) = default(4s);
        double IARP_eventDelay @unit(ms) = default(500ms);
        double IARP_eventJitter @unit(ms) = default(15ms);
        double linkStateLifetime @unit(s) = default(8s);
        double debugInterval @unit(s) = default(0s);
        double brpJitterMax @unit(s) = default(0.1s);
        double brpCoverageLifetime @unit(s) = default(30s);
        double ierpRetryInterval @unit(s) = default(2s);
        int ierpMaxRetries = default(3);
        double delayedPacketLifetime @unit(s) = default(8s);

        @display("i=block/network2");

    gates:
        input socketIn;
        output socketOut;

    submodules:
        protocol: GzrpProtocol {
            parameters:
                // routingTableModule / interfaceTableModule / networkProtocolModule
                // intentionally NOT forwarded via parent.X here -- that does a
                // literal string copy which OMNeT++ does NOT depth-adjust, so a
                // value of "^.ipv4.routingTable" stored on the compound would
                // resolve from this inner module to <compound>.ipv4.routingTable
                // and fail. Letting the inner's own ^.^.* defaults apply (or
                // letting an .ini wildcard like **.routingTableModule="^.ipv4.X"
                // hit this submodule directly, which IS depth-adjusted) gets the
                // path right.
                udpPort = parent.udpPort;
                interface = parent.interface;
                enableOriginatorPreDecay = parent.enableOriginatorPreDecay;
                emaAlpha = parent.emaAlpha;
                ierpReplyInstallPolicy = parent.ierpReplyInstallPolicy;
                NDP_helloInterval = parent.NDP_helloInterval;
                IARP_updateInterval = parent.IARP_updateInterval;
                IARP_eventDelay = parent.IARP_eventDelay;
                IARP_eventJitter = parent.IARP_eventJitter;
                linkStateLifetime = parent.linkStateLifetime;
                debugInterval = parent.debugInterval;
                brpJitterMax = parent.brpJitterMax;
                brpCoverageLifetime = parent.brpCoverageLifetime;
                ierpRetryInterval = parent.ierpRetryInterval;
                ierpMaxRetries = parent.ierpMaxRetries;
                delayedPacketLifetime = parent.delayedPacketLifetime;
                @display("p=100,100");
        }
        scoring:   <> like IScoringStrategy   { @display("p=200,50"); }
        decay:     <> like IDecayStrategy     { @display("p=200,100"); }
        gate:      <> like IGateStrategy      { @display("p=200,150"); }
        threshold: <> like IThresholdStrategy { @display("p=200,200"); }
    connections allowunconnected:
        socketIn --> protocol.socketIn;
        protocol.socketOut --> socketOut;
}


//
// The C++-class-bound simple module. The Gzrp class lives here; all
// @signal/@statistic declarations are on this module so emit() inside C++
// reaches them.
//
simple GzrpProtocol
{
    parameters:
        @class("inet::gzrp::Gzrp");

        // Two-level ^ because this simple module lives one extra level
        // deep inside the Gzrp compound -- see the compound's matching
        // defaults above.
        string routingTableModule = default("^.^.ipv4.routingTable");
        string interfaceTableModule = default("^.^.interfaceTable");
        string networkProtocolModule = default("^.^.ipv4.ip");
        int udpPort = default(654);
        string interface = default("wlan0");

        bool enableOriginatorPreDecay = default(true);
        double emaAlpha = default(0.3);
        string ierpReplyInstallPolicy = default("stability-hops");

        double NDP_helloInterval @unit(s) = default(1s);
        double IARP_updateInterval @unit(s) = default(4s);
        double IARP_eventDelay @unit(ms) = default(500ms);
        double IARP_eventJitter @unit(ms) = default(15ms);
        double linkStateLifetime @unit(s) = default(8s);
        double debugInterval @unit(s) = default(0s);
        double brpJitterMax @unit(s) = default(0.1s);
        double brpCoverageLifetime @unit(s) = default(30s);
        double ierpRetryInterval @unit(s) = default(2s);
        int ierpMaxRetries = default(3);
        double delayedPacketLifetime @unit(s) = default(8s);

        @signal[controlPacketSent](type=inet::Packet);
        @statistic[controlPacketSent](title="control packets sent"; source=controlPacketSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @signal[routeDiscoveryStarted];
        @statistic[routeDiscoveryStarted](title="route discoveries initiated (first attempt only)"; source=routeDiscoveryStarted; record=count,vector; interpolationmode=none);
        @signal[routeDiscoveryRetried];
        @statistic[routeDiscoveryRetried](title="route discovery retransmissions (driven by ierpRetryInterval)"; source=routeDiscoveryRetried; record=count,vector; interpolationmode=none);

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

        @signal[routeLength];
        @statistic[routeLength](title="hop count of newly-discovered IERP routes (at source)"; source=routeLength; record=count,sum,mean,vector; interpolationmode=none);
        @signal[routeDiscoveryTime];
        @statistic[routeDiscoveryTime](title="elapsed time from first IERP query to arriving reply (at source)"; source=routeDiscoveryTime; record=count,sum,mean,vector; interpolationmode=none);

    gates:
        input socketIn;
        output socketOut;
}
