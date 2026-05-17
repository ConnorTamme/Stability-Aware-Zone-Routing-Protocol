//
// Per-node multiplicative decay used to recover SAZRP. Each forwarder
// multiplies the running stability by its own beta in [betaMin, betaMax],
// interpolated from that node's fractionGood so cluster-core nodes decay
// slowly and just-passing nodes decay aggressively.
//

#ifndef GZRP_STRATEGIES_MULTIPLICATIVEBETADECAY_H_
#define GZRP_STRATEGIES_MULTIPLICATIVEBETADECAY_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API MultiplicativeBetaDecay : public IDecayStrategy {
  protected:
    double betaMin = 0.7;
    double betaMax = 0.85;

    double betaFor(const SelfState& self) const;

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual uint8_t initialState(const SelfState& self) override;
    virtual uint8_t decayState(uint8_t prev, const SelfState& self) override;
    virtual bool isAdmissible(uint8_t byteIn, double threshold) override;
    virtual bool shouldForward(uint8_t byteAfter, double threshold) override;
    virtual double decayValueForDijkstra(double running, int hops, const SelfState& self) override;
    virtual bool peripheralByHopBudget() const override { return false; }
    // SAZRP parity: SAZRP's std::priority_queue<pair<double,L3Address>> pops
    // the LARGEST address on value ties. Match that here so GZRP-Sazrp's
    // Dijkstra produces the same prev-chain / next-hop pick as SAZRP.
    virtual bool tiebreakPrefersLargerAddr() const override { return true; }
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_MULTIPLICATIVEBETADECAY_H_
