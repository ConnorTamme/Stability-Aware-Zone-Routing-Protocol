//
// Thin subclass of inetmanet OLSR that emits the common FANET-experiment
// control-packet statistics signal. OLSR is proactive, so no
// routeDiscoveryStarted signal is declared or emitted.
//

#ifndef SA_ZRP_STATS_OLSRWITHSTATS_H_
#define SA_ZRP_STATS_OLSRWITHSTATS_H_

#include "inet/routing/extras/olsr/Olrs.h"

namespace inet {
namespace inetmanet {

class INET_API OlsrWithStats : public Olsr
{
  public:
    static simsignal_t controlPacketSentSignal;

  protected:
    virtual void send_pkt() override;
};

} // namespace inetmanet
} // namespace inet

#endif // SA_ZRP_STATS_OLSRWITHSTATS_H_
