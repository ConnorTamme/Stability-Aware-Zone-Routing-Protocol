//
// Trivial gate that always admits. Used to recover stock ZRP where there
// is no per-node admit/forward gating.
//

#ifndef GZRP_STRATEGIES_ALWAYSADMITGATE_H_
#define GZRP_STRATEGIES_ALWAYSADMITGATE_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API AlwaysAdmitGate : public IGateStrategy {
  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual bool nodePassesGate(const SelfState&, double) override { return true; }
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_ALWAYSADMITGATE_H_
