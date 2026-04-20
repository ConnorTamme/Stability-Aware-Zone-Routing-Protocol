//
// FANET search-and-rescue scenario: all-to-one, 1500x3000x50 m.
// UAVs follow BonnMotion RPGM (Reference Point Group Mobility) traces,
// organised into 3 groups. Base station sits at the edge (0, 1500, 0).
//

package sa_zrp.simulations.FanetSar;

import inet.environment.common.PhysicalEnvironment;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.contract.INetworkNode;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.common.IntegratedMultiVisualizer;

network FanetSarNetwork
{
    parameters:
        int numUavs = default(30);
        @display("bgb=1500,3000");

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
            @display("p=0,1500;i=device/antennatower");
        }
}
