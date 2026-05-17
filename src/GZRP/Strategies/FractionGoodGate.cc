#include "FractionGoodGate.h"

namespace inet {
namespace gzrp {

Define_Module(FractionGoodGate);

void FractionGoodGate::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        q = par("q");
    }
}

bool FractionGoodGate::nodePassesGate(const SelfState& self, double)
{
    return fractionGoodOf(self) >= q;
}

} // namespace gzrp
} // namespace inet
