#include "MultiplicativeBetaDecay.h"

namespace inet {
namespace gzrp {

Define_Module(MultiplicativeBetaDecay);

void MultiplicativeBetaDecay::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        betaMin = par("betaMin");
        betaMax = par("betaMax");
        if (betaMax < betaMin)
            throw cRuntimeError("betaMax (%g) must be >= betaMin (%g)", betaMax, betaMin);
    }
}

double MultiplicativeBetaDecay::betaFor(const SelfState& self) const
{
    // Setting betaMin == betaMax collapses the per-node beta to a fixed
    // value, recovering the v2 fixed-decay semantics.
    return betaMin + (betaMax - betaMin) * fractionGoodOf(self);
}

uint8_t MultiplicativeBetaDecay::initialState(const SelfState&)
{
    return 255;
}

uint8_t MultiplicativeBetaDecay::decayState(uint8_t prev, const SelfState& self)
{
    return encodeStability(decodeStability(prev) * betaFor(self));
}

bool MultiplicativeBetaDecay::isAdmissible(uint8_t byteIn, double tau)
{
    return decodeStability(byteIn) >= tau;
}

bool MultiplicativeBetaDecay::shouldForward(uint8_t byteAfter, double tau)
{
    return decodeStability(byteAfter) >= tau;
}

double MultiplicativeBetaDecay::decayValueForDijkstra(double running, int, const SelfState& self)
{
    return betaFor(self) * running;
}

} // namespace gzrp
} // namespace inet
