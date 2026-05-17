//
// SAZRP fringe gate: a node only originates / admits / forwards an IARP
// grenade when at least fraction q of its neighbours have quality >= tau.
// Reads tau from SelfState.threshold so the gate uses the same threshold
// the decay does.
//

#ifndef GZRP_STRATEGIES_FRACTIONGOODGATE_H_
#define GZRP_STRATEGIES_FRACTIONGOODGATE_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API FractionGoodGate : public IGateStrategy {
  protected:
    double q = 0.5;

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual bool nodePassesGate(const SelfState& self, double threshold) override;
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_FRACTIONGOODGATE_H_
