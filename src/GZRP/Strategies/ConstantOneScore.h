//
// Trivial scoring strategy: every link gets quality 1.0. Used to recover
// stock ZRP (no link-quality signal, hop-count zones only).
//

#ifndef GZRP_STRATEGIES_CONSTANTONESCORE_H_
#define GZRP_STRATEGIES_CONSTANTONESCORE_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API ConstantOneScore : public IScoringStrategy {
  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual double scoreLink(const SelfState& self, const NeighbourState& nbr) override;
    virtual size_t helloExtensionLength() override { return 0; }
    virtual void populateHelloExtension(NDP_Hello* hello, const SelfState& self) override;
    virtual void parseHelloExtension(const NDP_Hello* hello, NeighbourState& nbr) override;
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_CONSTANTONESCORE_H_
