//
// Test network for ZRP based on INET's ManetprotocolsShowcaseB
//

package sa_zrp.simulations.ZrpTest;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.ManetRouter;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.common.IntegratedMultiVisualizer;

// Simple test network with stationary nodes for basic ZRP testing
network ZrpTestNetwork
{
    parameters:
        @display("bgb=400,400");

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
            @display("p=104,335");
        }

        // Destination node
        destination: ManetRouter {
            @display("p=292,80");
        }

        // Intermediate nodes to form multi-hop paths
        node1: ManetRouter {
            @display("p=104,226");
        }
        node2: ManetRouter {
            @display("p=175,140");
        }
        node3: ManetRouter {
            @display("p=238,276");
        }
        node4: ManetRouter {
            @display("p=312,196");
        }
        node5: ManetRouter {
            @display("p=147,67");
        }
        node6: ManetRouter {
            @display("p=60,125");
        }
}

// Network with mobile nodes for testing ZRP under mobility
network ZrpMobileTestNetwork extends ZrpTestNetwork
{
    parameters:
        @display("bgb=400,400");
}
