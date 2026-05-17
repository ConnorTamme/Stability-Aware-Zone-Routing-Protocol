#include "ConstantThreshold.h"

namespace inet {
namespace gzrp {

Define_Module(ConstantThreshold);

void ConstantThreshold::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        value = par("value");
    }
}

} // namespace gzrp
} // namespace inet
