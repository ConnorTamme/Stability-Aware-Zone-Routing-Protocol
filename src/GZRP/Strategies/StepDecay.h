//
// Hop-count decay used to recover stock ZRP. The runningStability byte
// counts hops travelled; admission and forwarding stop once the byte
// exceeds radius. Threshold tau is unused by this decay; gates and
// thresholds operate on the [0,1] scale where StepDecay emits {0,1}.
//

#ifndef GZRP_STRATEGIES_STEPDECAY_H_
#define GZRP_STRATEGIES_STEPDECAY_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API StepDecay : public IDecayStrategy {
  protected:
    int radius = 2;

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual uint8_t initialState(const SelfState& self) override;
    virtual uint8_t decayState(uint8_t prev, const SelfState& self) override;
    virtual bool isAdmissible(uint8_t byteIn, double threshold) override;
    virtual bool shouldForward(uint8_t byteAfter, double threshold) override;
    virtual double decayValueForDijkstra(double running, int hops, const SelfState& self) override;
    virtual bool peripheralByHopBudget() const override { return true; }
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_STEPDECAY_H_
