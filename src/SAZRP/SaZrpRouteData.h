//
//  Header file defining SaZrpRouteData. This is metadata attached to SAZRP routes used for IERP.
//  Mirrors the baseline ZrpRouteData in namespace inet::zrp.
//

#ifndef SAZRPROUTEDATA_H_
#define SAZRPROUTEDATA_H_

#include <vector>
#include <sstream>

#include "inet/networklayer/common/L3Address.h"

namespace inet {
namespace sazrp {

enum SaZrpRouteType { SAZRP_ROUTE_IARP, SAZRP_ROUTE_IERP };

// Metadata attached to SAZRP routes in the routing table. Based on AODV.
// Has the full route path for IERP routes to allow maintenance and shortening.
class INET_API SaZrpRouteData : public cObject {
  protected:
    SaZrpRouteType routeType;

    // The full source route from source to destination, including endpoints.
    std::vector<L3Address> sourceRoute;

    // When this route was last confirmed/discovered
    simtime_t discoveryTime;

    // Whether this route is currently active (data can flow)
    bool active;

  public:
    SaZrpRouteData(SaZrpRouteType type = SAZRP_ROUTE_IARP) : routeType(type), discoveryTime(SIMTIME_ZERO), active(true) {}

    virtual ~SaZrpRouteData() {}

    SaZrpRouteType getRouteType() const { return routeType; }
    void setRouteType(SaZrpRouteType type) { this->routeType = type; }

    bool isIarpRoute() const { return routeType == SAZRP_ROUTE_IARP; }
    bool isIerpRoute() const { return routeType == SAZRP_ROUTE_IERP; }

    const std::vector<L3Address>& getSourceRoute() const { return sourceRoute; }
    void setSourceRoute(const std::vector<L3Address>& route) { this->sourceRoute = route; }

    size_t getSourceRouteLength() const { return sourceRoute.size(); }

    const simtime_t& getDiscoveryTime() const { return discoveryTime; }
    void setDiscoveryTime(const simtime_t& t) { this->discoveryTime = t; }

    bool isActive() const { return active; }
    void setIsActive(bool a) { this->active = a; }

    virtual std::string str() const override
    {
        std::ostringstream out;
        out << "type=" << (routeType == SAZRP_ROUTE_IARP ? "IARP" : "IERP");
        out << ", active=" << (active ? "true" : "false");
        out << ", discovered=" << discoveryTime;

        if (routeType == SAZRP_ROUTE_IERP && !sourceRoute.empty()) {
            out << ", route=[";
            for (size_t i = 0; i < sourceRoute.size(); i++) {
                if (i > 0)
                    out << " -> ";
                out << sourceRoute[i];
            }
            out << "]";
        }

        return out.str();
    }
};

} // namespace sazrp
} // namespace inet

#endif // SAZRPROUTEDATA_H_
