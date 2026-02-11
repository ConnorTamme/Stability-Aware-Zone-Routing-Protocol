//
// Test network for ZRP based on INET's ManetprotocolsShowcaseB
//

package sa_zrp.simulations.ZrpTestBig;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.ManetRouter;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.common.IntegratedMultiVisualizer;

// Simple test network with stationary nodes for basic ZRP testing
network ZrpTestNetworkBig
{
    parameters:
        @display("bgb=700,700");

        // Statistics for ping replies (ping app must be app[0] on source)
        @statistic[numRcvdPk](source=count(source.app[0].pingRxSeq); record=figure; targetFigure=numRcvdPkCounter; checkSignals=false);
        @figure[numRcvdPkCounter](type=counter; transform=scale(0.5); pos=50,300; label="Received ping replies"; decimalPlaces=4);

        @statistic[numLost](source=count(source.app[0].numLost); record=figure; targetFigure=numLostPkCounter; checkSignals=false);
        @figure[numLostPkCounter](type=counter; transform=scale(0.5); pos=50,350; label="Pings lost"; decimalPlaces=4);

    submodules:
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=38,28");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=38,67");
        }
        visualizer: IntegratedMultiVisualizer {
            @display("p=38,107");
        }

        // Source node (will ping destination)
        source: ManetRouter {
            @display("p=93,614");
        }

        // Destination node
        destination: ManetRouter {
            @display("p=372,297");
        }

        // Intermediate nodes to form multi-hop paths
        node1: ManetRouter {
            @display("p=93,506");
        }
        node2: ManetRouter {
            @display("p=135,288");
        }
        node3: ManetRouter {
            @display("p=192,575");
        }
        node4: ManetRouter {
            @display("p=400,389");
        }
        node5: ManetRouter {
            @display("p=257,258");
        }
        node6: ManetRouter {
            @display("p=302,342");
        }
        node7: ManetRouter {
            @display("p=309,444");
        }
        node8: ManetRouter {
            @display("p=392,495");
        }
        node9: ManetRouter {
            @display("p=201,342");
        }
        node10: ManetRouter {
            @display("p=289,548");
        }
        node11: ManetRouter {
            @display("p=201,467");
        }
        node12: ManetRouter {
            @display("p=93,389");
        }
}

