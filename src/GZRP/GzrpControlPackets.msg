//
// Defines the packets for GZRP (Generalised ZRP).
//
// NDP_Hello carries a strategy-owned helloExtension byte blob whose
// interpretation is delegated to the scoring strategy (ConstantOneScore
// writes nothing, LparStabilityScore writes 6 floats). IARP_LinkStateUpdate
// keeps the SAZRP-derived runningStability byte but its meaning is now
// decay-strategy-owned (hop count for StepDecay, quantised path stability
// for MultiplicativeBetaDecay).
//

cplusplus {{
// IARP metric layout constants. Defined here (not in Gzrp.h) so the
// generated _m.h does not pull Gzrp.h, which would create a cycle through
// Strategies/IStrategy.h.
#define IARP_METRIC_COUNT 1
#define IARP_METRIC_STABILITY 2
}}

import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.common.packet.Packet;
import inet.networklayer.common.L3Address;

namespace inet::gzrp;

// Neighbour Discovery Protocol hello -- not in the original ZRP RFC, but
// every implementation needs one. GZRP makes the optional payload after
// nodeAddress/seqNum a variable-length byte array filled by the scoring
// strategy via populateHelloExtension.
class NDP_Hello extends FieldsChunk
{
    L3Address nodeAddress;
    uint16_t seqNum;
    uint8_t helloExtension[];
}

//
// IARP Link State Update Packet (wire layout inherited from SAZRP).
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
// runningStability is the byte the decay strategy emits/consumes. metricType
// is informational (GZRP keeps the SAZRP value IARP_METRIC_STABILITY=2);
// metricValue is the quantised per-link quality returned by the scoring
// strategy at advertisement time.

struct IARP_MetricData {
    uint8_t reserved = 0;
    uint8_t metricType;
    uint16_t metricValue;
};

struct IARP_LinkDestData
{
    @packetData;
    L3Address addr;
    IARP_MetricData metrics[IARP_METRIC_COUNT];
};

class IARP_LinkStateUpdate extends FieldsChunk
{
    L3Address sourceAddr;
    uint16_t seqNum;
    uint8_t radius = 0;        // unused; kept for layout parity
    uint8_t runningStability;  // wire byte; meaning is decay-strategy-owned
    uint16_t reserved1 = 0;
    uint8_t reserved2 = 0;
    uint8_t linkDestCount;
    IARP_LinkDestData linkDestData[];
}

//IERP Packet from RFC (unchanged from SAZRP beyond the namespace rename)
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
    uint8_t length;            // Total packet length in multiples of 4 bytes
    uint8_t nodePtr;
    uint8_t reserved1 = 0;
    uint16_t queryID;
    uint16_t reserved2 = 0;
    L3Address sourceAddr;
    L3Address intermediateNodes[];
    L3Address destAddr;
}

//BRP Packet from RFC (unchanged from SAZRP beyond the namespace rename)

class BRP_Data extends FieldsChunk
{
    L3Address sourceAddr;
    L3Address destAddr;
    uint16_t queryID;
    uint8_t queryExtension;
    uint8_t reserved = 0;
    L3Address prevBordercastAddr;
    IERP_RouteData encapsulatedPacket;
}
