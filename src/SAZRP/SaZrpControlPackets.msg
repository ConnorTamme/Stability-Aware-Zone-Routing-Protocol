//
// Defines the packets for SAZRP (Stability-Aware ZRP)
//


//Includes the SaZrp.h so we can use a macro from it
cplusplus {{
#include "SaZrp.h"
}}

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.common.packet.Packet;
import inet.networklayer.common.L3Address;

namespace inet::sazrp;

//The Neighbour Discovery Protocol is not included in the RFC so this is used to obtain neighbouring nodes.
//SAZRP extends the Hello with the sender's current position and velocity so receivers can compute
//the LPAR per-link stability score.
class NDP_Hello extends FieldsChunk
{
	L3Address nodeAddress;
	uint16_t seqNum;
	float posX;
	float posY;
	float posZ;
	float velX;
	float velY;
	float velZ;
}


//
// IARP Link State Update Packet from RFC, repurposed for SAZRP.
//
// The layout matches the baseline ZRP packet (wire-compatible size per record)
// but the former TTL field is repurposed as a one-byte quantized running
// stability value r in [0,1] used for flood termination. The former 'radius'
// field is kept only for layout parity and is never read; it stays zero.
//
//                       1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Link Source Address                     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Link State Seq Num      |    UNUSED     |runningStability|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          RESERVED             |   RESERVED    | Link Dest Cnt |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Link Destination 1 Address                 |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |   RESERVED    |  Metric Type  |          Metric Value         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   ...
//
// In SAZRP, metricType = IARP_METRIC_STABILITY (2) and metricValue is the
// quantized smoothed stability floor(sbar * 255) for that neighbour (low byte).


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
	uint8_t radius = 0; // unused in SAZRP; kept for layout parity only
	uint8_t runningStability; // repurposed former TTL: r in [0,1] quantized to one byte
	uint16_t reserved1 = 0;
	uint8_t reserved2 = 0;
	uint8_t linkDestCount; //The number of neighbours the source has
	IARP_LinkDestData linkDestData[];
}

//IERP Packet from RFC (unchanged in SAZRP beyond the namespace rename)
//
//                        1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |     Type      |     Length    |    Node Ptr   |    RESERVED   |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           Query ID            |        R E S E R V E D        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                  Query/Route Source Address                   |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                 Intermediate Node (1) Address                 |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    ...
//    |                Query/Route Destination Address                |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

enum IERP_Type
{
	IERP_QUERY = 1;
	IERP_REPLY = 2;
};

class IERP_RouteData extends FieldsChunk
{
	uint8_t type;
	uint8_t length; //Total packet length in multiples of 4 bytes
	uint8_t nodePtr;
	uint8_t reserved1 = 0;
	uint16_t queryID;
	uint16_t reserved2 = 0;
	L3Address sourceAddr;
	L3Address intermediateNodes[]; //The number of intermediate nodes is determined by the length field
	L3Address destAddr;
}


//BRP Packet from RFC (unchanged in SAZRP beyond the namespace rename)

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
