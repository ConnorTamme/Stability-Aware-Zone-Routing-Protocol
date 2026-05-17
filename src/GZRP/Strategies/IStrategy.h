//
// Strategy interfaces and shared types for the Generalised Zone Routing
// Protocol (GZRP). The four decisions in a ZRP-family protocol --
// per-link scoring, hop-by-hop decay, per-node admit/forward gate, and
// the threshold used by gate/decay -- are each delegated to a swappable
// cSimpleModule submodule.
//

#ifndef GZRP_STRATEGIES_ISTRATEGY_H_
#define GZRP_STRATEGIES_ISTRATEGY_H_

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>

#include "inet/common/geometry/common/Coord.h"
#include "inet/networklayer/common/L3Address.h"
#include "omnetpp.h"

#include "../GzrpControlPackets_m.h"

namespace inet {
namespace gzrp {

struct NeighbourState {
    L3Address addr;
    double quality = 0.0;              // last value returned by scoring->scoreLink
    simtime_t lastHeard = SIMTIME_ZERO;
    Coord lastPos;                     // optional, only used by strategies that
    Coord lastVel;                     //   populate the Hello extension
};

struct SelfState {
    // Borrowed from Gzrp. May be null at startup before the first sample arrives;
    // strategies must treat a null or empty map as "no information yet" (see
    // fractionGoodOf below).
    const std::map<L3Address, NeighbourState>* neighbours = nullptr;
    Coord pos;
    Coord vel;
    // Resolved by Gzrp from IThresholdStrategy::threshold before the SelfState
    // is passed to gate/decay. To bootstrap this resolution Gzrp first builds a
    // partial SelfState with threshold=0 and feeds it to threshold->threshold();
    // strategies that don't depend on self info therefore see a zero in that
    // bootstrap call and must not rely on it.
    double threshold = 0.0;
};

class IScoringStrategy : public omnetpp::cSimpleModule {
  public:
    // Compute the per-link quality for an observation of a neighbour. The
    // returned value is what the IARP wire metric encodes (after quantisation)
    // and what the gate strategies see in NeighbourState::quality.
    virtual double scoreLink(const SelfState& self, const NeighbourState& nbr) = 0;
    // Number of bytes this scoring strategy needs to piggyback on each
    // NDP_Hello. Gzrp uses this to size the helloExtension byte array before
    // calling populateHelloExtension.
    virtual size_t helloExtensionLength() = 0;
    // Serialise scoring-specific state (e.g. position, velocity) into the
    // Hello extension byte array.
    virtual void populateHelloExtension(NDP_Hello* hello, const SelfState& self) = 0;
    // Deserialise the matching state from a received Hello into the neighbour
    // record we are about to score.
    virtual void parseHelloExtension(const NDP_Hello* hello, NeighbourState& nbr) = 0;
    // True iff scoreLink / populateHelloExtension actually read SelfState::pos
    // or SelfState::vel. Gzrp::buildSelfState consults this before calling
    // mobility->getCurrentPosition() / getCurrentVelocity() -- those calls go
    // through MovingMobilityBase::moveAndUpdate() which emits the
    // mobilityStateChangedSignal and advances per-module bookkeeping on every
    // first-of-simtime call. ZRP never touches mobility, so for GZRP-Classic
    // (ConstantOneScore, no kinematics) we must skip the call too -- otherwise
    // GZRP's protocol-event-driven mobility queries make the two protocols'
    // event streams diverge even when their routing decisions agree.
    virtual bool needsKinematics() const { return false; }
};

class IDecayStrategy : public omnetpp::cSimpleModule {
  public:
    // Wire value carried on the IARP grenade when the originator sends. Result
    // is encoded into the runningStability byte of IARP_LinkStateUpdate.
    virtual uint8_t initialState(const SelfState& self) = 0;
    // Per-hop wire update applied by an admitting forwarder before
    // rebroadcasting. prev is the byte we received; we return the byte we
    // would send.
    virtual uint8_t decayState(uint8_t prev, const SelfState& self) = 0;
    // Whether an incoming runningStability byte clears the receiver's
    // admission rule (e.g. for SAZRP r_in >= tau).
    virtual bool isAdmissible(uint8_t byteIn, double threshold) = 0;
    // Whether a freshly-decayed byte clears the forward rule. May differ from
    // isAdmissible in admit-only-then-stop decays.
    virtual bool shouldForward(uint8_t byteAfter, double threshold) = 0;
    // Dijkstra relaxation FROM a forwarder: given the running value at the
    // forwarder and the new hop count after relaxation, return the running
    // value at the receiver. Gzrp uses this on each edge of its widest-path
    // (or hop-bounded) computation, applying enableOriginatorPreDecay
    // explicitly at u==self.
    virtual double decayValueForDijkstra(double running, int hops, const SelfState& self) = 0;

    // Peripheral semantic. Returns true if peripherals should be derived
    // from the Dijkstra frontier ("v is peripheral iff its outgoing
    // relaxation would be pruned by decay") -- the positional definition
    // used by classic ZRP (metric == zoneRadius). Returns false if
    // peripherals should be derived from the topological rule ("v is
    // peripheral iff it has at least one out-of-zone neighbour per the
    // local linkStateTable view") -- the definition used by SAZRP, where
    // the grenade overshoots the zone and the value-frontier and the
    // topological-frontier are different sets.
    //
    // Concretely: StepDecay returns true (hop-bounded, recovers ZRP);
    // MultiplicativeBetaDecay returns false (value-bounded, recovers
    // SAZRP). This split lets BRP_isOutNeighbour pick the right peripheral
    // derivation rooted at a remote previous bordercaster, where the
    // linkStateTable proxy used by self-rooted code does not work for
    // hop-bounded decay (the linkstate-availability boundary is rooted at
    // us, not at the prev bordercaster).
    virtual bool peripheralByHopBudget() const = 0;

    // Dijkstra address-tiebreak direction for value/hop ties. ZRP uses a
    // min-heap on (dist, addr) which pops the SMALLEST address first; SAZRP
    // uses a default max-heap on (value, addr) which pops the LARGEST. The
    // two implementations made opposite arbitrary choices and the GZRP
    // Dijkstra has to match each. StepDecay returns false (smallest-addr
    // tiebreak -> ZRP parity); MultiplicativeBetaDecay returns true
    // (largest-addr tiebreak -> SAZRP parity). The choice is cosmetic for
    // the routes' correctness but determines which equal-cost next-hop is
    // recorded, and downstream MAC contention cascades from that pick.
    virtual bool tiebreakPrefersLargerAddr() const { return false; }
};

class IGateStrategy : public omnetpp::cSimpleModule {
  public:
    // Whether a node would (a) originate a grenade, (b) admit/forward an
    // arriving one, and (c) act as an intermediate forwarder in the Dijkstra.
    // tau is passed in alongside self.threshold for callers that pre-resolved
    // it; strategies that need it read from self.threshold for consistency
    // with how the decay reads it.
    virtual bool nodePassesGate(const SelfState& self, double threshold) = 0;
};

class IThresholdStrategy : public omnetpp::cSimpleModule {
  public:
    // The threshold tau used uniformly by gate and decay strategies for one
    // resolution of a Gzrp logical decision. May depend on self state in
    // future extensions; the bootstrap call from buildSelfState passes a
    // SelfState whose threshold field is 0, so threshold strategies that
    // don't need self info simply ignore it.
    virtual double threshold(const SelfState& self) = 0;
};

// Shared utility used by both Sazrp-style decay and Sazrp-style gate.
// Returns 1.0 for an empty or unknown neighbour set so a freshly-started
// node is treated as "passable" until it has samples (mirrors existing
// SAZRP defensive startup behaviour -- without this nodes would deadlock,
// refusing to flood until someone else flooded first).
inline double fractionGoodOf(const SelfState& s)
{
    if (!s.neighbours || s.neighbours->empty())
        return 1.0;
    size_t good = 0;
    for (const auto& kv : *s.neighbours)
        if (kv.second.quality >= s.threshold)
            ++good;
    return static_cast<double>(good) / static_cast<double>(s.neighbours->size());
}

// Quantisation: byte <-> double in [0,1]. Mirrors the SAZRP wire layout so
// the runningStability and IARP per-link metric stay binary compatible.
inline double decodeStability(uint8_t q)
{
    return static_cast<double>(q) / 255.0;
}

inline uint8_t encodeStability(double s)
{
    double c = std::max(0.0, std::min(1.0, s));
    return static_cast<uint8_t>(std::floor(c * 255.0));
}

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_ISTRATEGY_H_
