#include "LparStabilityScore.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace inet {
namespace gzrp {

Define_Module(LparStabilityScore);

namespace {
inline double clamp01(double v)
{
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}
} // namespace

void LparStabilityScore::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        commsRange = par("commsRange");
        vMax = par("vMax");
        distanceExponent = par("distanceExponent");
    }
}

double LparStabilityScore::scoreLink(const SelfState& self, const NeighbourState& nbr)
{
    Coord disp = self.pos - nbr.lastPos;
    double d = disp.length();
    Coord relVel = self.vel - nbr.lastVel;
    double Vrel = relVel.length();

    // d/dt |p_self - p_sender| has the sign of disp . relVel: positive =>
    // diverging, so we apply the speed-aware penalty.
    double dot = disp.x * relVel.x + disp.y * relVel.y + disp.z * relVel.z;
    bool diverging = (dot > 0.0);

    double D = clamp01(1.0 - std::pow(d / commsRange, distanceExponent));
    double Y = diverging ? clamp01(1.0 - Vrel / (2.0 * vMax)) : 1.0;
    return D * Y;
}

void LparStabilityScore::populateHelloExtension(NDP_Hello* hello, const SelfState& self)
{
    float buf[6];
    buf[0] = static_cast<float>(self.pos.x);
    buf[1] = static_cast<float>(self.pos.y);
    buf[2] = static_cast<float>(self.pos.z);
    buf[3] = static_cast<float>(self.vel.x);
    buf[4] = static_cast<float>(self.vel.y);
    buf[5] = static_cast<float>(self.vel.z);

    uint8_t bytes[sizeof(buf)];
    std::memcpy(bytes, buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i)
        hello->setHelloExtension(i, bytes[i]);
}

void LparStabilityScore::parseHelloExtension(const NDP_Hello* hello, NeighbourState& nbr)
{
    constexpr size_t expected = 6 * sizeof(float);
    if (hello->getHelloExtensionArraySize() < expected)
        return;

    uint8_t bytes[expected];
    for (size_t i = 0; i < expected; ++i)
        bytes[i] = hello->getHelloExtension(i);

    float buf[6];
    std::memcpy(buf, bytes, sizeof(buf));
    nbr.lastPos = Coord(buf[0], buf[1], buf[2]);
    nbr.lastVel = Coord(buf[3], buf[4], buf[5]);
}

} // namespace gzrp
} // namespace inet
