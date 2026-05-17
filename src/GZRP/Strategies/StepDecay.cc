#include "StepDecay.h"

namespace inet {
namespace gzrp {

Define_Module(StepDecay);

void StepDecay::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        radius = par("radius");
    }
}

uint8_t StepDecay::initialState(const SelfState&)
{
    return 1;
}

uint8_t StepDecay::decayState(uint8_t prev, const SelfState&)
{
    int next = static_cast<int>(prev) + 1;
    if (next > 255) next = 255;
    return static_cast<uint8_t>(next);
}

bool StepDecay::isAdmissible(uint8_t byteIn, double)
{
    return static_cast<int>(byteIn) <= radius;
}

bool StepDecay::shouldForward(uint8_t byteAfter, double)
{
    return static_cast<int>(byteAfter) <= radius;
}

double StepDecay::decayValueForDijkstra(double, int hops, const SelfState&)
{
    return (hops <= radius) ? 1.0 : 0.0;
}

} // namespace gzrp
} // namespace inet
