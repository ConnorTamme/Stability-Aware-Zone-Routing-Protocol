//
// LPAR-style per-link scoring used by SAZRP. Couples a distance-based
// closeness D = 1 - (d/R)^p with a divergence-aware Y term (relative speed
// scaled by 2*vMax). The product D*Y is the quality reported per link.
//

#ifndef GZRP_STRATEGIES_LPARSTABILITYSCORE_H_
#define GZRP_STRATEGIES_LPARSTABILITYSCORE_H_

#include "IStrategy.h"

namespace inet {
namespace gzrp {

class INET_API LparStabilityScore : public IScoringStrategy {
  protected:
    double commsRange = 0.0;
    double vMax = 0.0;
    double distanceExponent = 4.0;

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

  public:
    virtual double scoreLink(const SelfState& self, const NeighbourState& nbr) override;
    virtual size_t helloExtensionLength() override { return 6 * sizeof(float); }
    virtual void populateHelloExtension(NDP_Hello* hello, const SelfState& self) override;
    virtual void parseHelloExtension(const NDP_Hello* hello, NeighbourState& nbr) override;
    virtual bool needsKinematics() const override { return true; }
};

} // namespace gzrp
} // namespace inet

#endif // GZRP_STRATEGIES_LPARSTABILITYSCORE_H_
