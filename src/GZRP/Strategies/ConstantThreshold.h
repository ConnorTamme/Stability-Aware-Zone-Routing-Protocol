//
// Fixed tau threshold. Sufficient to recover both stock ZRP (where tau is
// irrelevant) and SAZRP (where tau is the path-stability cutoff).
//

#ifndef GZRP_STRATEGIES_CONSTANTTHRESHOLD_H_
#define GZRP_STRATEGIES_CONSTANTTHRESHOLD_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API ConstantThreshold : public IThresholdStrategy {
  protected:
    double value = 0.3;

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual double threshold(const SelfState&) override { return value; }
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_CONSTANTTHRESHOLD_H_
