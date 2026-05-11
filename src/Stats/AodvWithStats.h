//
// Thin subclass of INET's AODV that emits the common FANET-experiment
// statistics signals (controlPacketSent, routeDiscoveryStarted) without
// modifying the vendor implementation.
//

#ifndef SA_ZRP_STATS_AODVWITHSTATS_H_
#define SA_ZRP_STATS_AODVWITHSTATS_H_

#include "inet/routing/aodv/Aodv.h"

namespace inet {
namespace aodv {

class INET_API AodvWithStats : public Aodv
{
  public:
    static simsignal_t controlPacketSentSignal;
    static simsignal_t routeDiscoveryStartedSignal;

  protected:
    virtual void sendAODVPacket(const Ptr<AodvControlPacket>& packet,
                                const L3Address& destAddr,
                                unsigned int timeToLive,
                                double delay) override;
    virtual void startRouteDiscovery(const L3Address& target,
                                     unsigned int timeToLive = 0) override;
};

} // namespace aodv
} // namespace inet

#endif // SA_ZRP_STATS_AODVWITHSTATS_H_
