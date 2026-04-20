//
// FANET controlled-stress scenario: 1000x1000 m 2D, no ground station.
// Traffic flows between 5 fixed UAV-to-UAV pairs (uav[0..4] -> uav[5..9]);
// any remaining UAVs act as forwarders only.
//

package sa_zrp.simulations.FanetStress;

import inet.environment.common.PhysicalEnvironment;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.contract.INetworkNode;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.common.IntegratedMultiVisualizer;

network FanetStressNetwork
{
    parameters:
        int numUavs = default(30);
        @display("bgb=1000,1000");

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
}
