#include "ConstantOneScore.h"

namespace inet {
namespace gzrp {

Define_Module(ConstantOneScore);

void ConstantOneScore::initialize(int stage)
{
    cSimpleModule::initialize(stage);
}

double ConstantOneScore::scoreLink(const SelfState&, const NeighbourState&)
{
    return 1.0;
}

void ConstantOneScore::populateHelloExtension(NDP_Hello*, const SelfState&)
{
}

void ConstantOneScore::parseHelloExtension(const NDP_Hello*, NeighbourState&)
{
}

} // namespace gzrp
} // namespace inet
