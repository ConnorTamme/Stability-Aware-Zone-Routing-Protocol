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


cplusplus {{
#include "Zrp.h"
}}

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.common.packet.Packet;
import inet.networklayer.common.L3Address;

namespace inet::zrp;

//The Neighbor Discovery Protocol is not included in the RFC so this is used to obtain neighboring nodes
class NDP_Hello extends FieldsChunk
{
	L3Address nodeAddress;
	uint16_t seqNum;
}


//
// IARP Link State Update Packet
//
//                       1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Link Source Address                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Link State Seq Num      |  Zone Radius  |      TTL      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          RESERVED             |   RESERVED    | Link Dest Cnt |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Link Destination 1 Address                 |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |            Link Destination 1 Subnet Mask  (Optional)         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ --+--
//   |   RESERVED    |  Metric Type  |          Metric Value         |   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Link
//   |   RESERVED    |  Metric Type  |          Metric Value         | Metrics
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
//   |   RESERVED    |  Metric Type  |          Metric Value         |   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ --+--
//                                 |  | 
//                                 |  | 
//                                \|  |/
//                                 \  /                                  
//                                  \/
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Link Destination n Address                 |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |            Link Destination n Subnet Mask  (Optional)         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ --+--
//   |   RESERVED    |  Metric Type  |          Metric Value         |   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Link
//   |   RESERVED    |  Metric Type  |          Metric Value         | Metrics
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
//   |   RESERVED    |  Metric Type  |          Metric Value         |   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ --+--
//


//All reserved fields are set to 0

struct IARP_MetricData{
	uint8_t reserved = 0;
	uint8_t metricType;
	uint16_t metricValue;
};


struct IARP_LinkDestData
{
	@packetData;
	L3Address addr; //Optional subnet mask not included
	IARP_MetricData metrics[IARP_METRIC_COUNT];
};



class IARP_LinkStateUpdate extends FieldsChunk
{
	L3Address sourceAddr;
	uint16_t seqNum;
	uint8_t radius;
	uint8_t TTL;
	uint16_t reserved1 = 0;
	uint8_t reserved2 = 0;
	uint8_t linkDestCount; //The number of neighbors the source has
	IARP_LinkDestData linkDestData[];
}

//IERP Packet
//
//                        1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |     Type      |     Length    |    Node Ptr   |    RESERVED   |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           Query ID            |        R E S E R V E D        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
//    |                  Query/Route Source Address                   |  
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+-
//    |                 Intermediate Node (1) Address                 |  |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
//    |                 Intermediate Node (2) Address                 |  |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
//                                   | |                                 |
//                                   | |                               route
//                                  \| |/                                |
//                                   \ /                                 |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|  |
//    |                Intermediate Node (N) Address                  |  |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
//    |                Query/Route Destination Address                |  |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+-

enum IERP_Type
{
	IERP_QUERY = 1;
	IERP_REPLY = 2;
};

class IERP_RouteData extends FieldsChunk
{
	uint8_t type;
	uint8_t length; //Total packet length in  multiples of 4 bytes
	uint8_t nodePtr;
	uint8_t reserved1 = 0;
	uint16_t queryID;
	uint16_t reserved2 = 0;
	L3Address sourceAddr;
	L3Address intermediateNodes[]; //The number of intermediate nodes is determined by the length field
	L3Address destAddr;
}


//BRP Packet
//
//	                     1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                       Query Source Address                    |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                    Query Destination Address                  |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |           Query ID            |Query Extension|    RESERVED   |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                    Prev Bordercast Address                    |   
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
//	 |                                                               |
//   |            E N C A P S U L A T E D     P A C K E T            |
// 	 |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class BRP_Data extends FieldsChunk
{
	L3Address sourceAddr;
	L3Address destAddr;
	uint16_t queryID;
	uint8_t queryExtension;
	uint8_t reserved = 0;
	L3Address prevBordercastAddr;
	IERP_RouteData encapsulatedPacket; //The packet being sent to the destination
}