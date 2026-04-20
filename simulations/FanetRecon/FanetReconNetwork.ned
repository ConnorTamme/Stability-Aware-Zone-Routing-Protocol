//
// FANET reconnaissance scenario: all-to-one, 3600x1200x200 m.
// UAVs follow BonnMotion Gauss-Markov traces; the ground station is
// stationary at the area centre.
//

package sa_zrp.simulations.FanetRecon;

import inet.environment.common.PhysicalEnvironment;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.contract.INetworkNode;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.common.IntegratedMultiVisualizer;

network FanetReconNetwork
{
    parameters:
        int numUavs = default(30);
        @display("bgb=3600,1200");

    submodules:
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=60,40");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=60,100");
        }
        physicalEnvironment: PhysicalEnvironment {
            @display("p=60,160");
        }
        visualizer: IntegratedMultiVisualizer {
            @display("p=60,220");
        }

        uav[numUavs]: <default("AdhocHost")> like INetworkNode {
            @display("i=device/airplane");
        }

        groundStation: <default("AdhocHost")> like INetworkNode {
            @display("p=1800,600;i=device/antennatower");
        }
}
