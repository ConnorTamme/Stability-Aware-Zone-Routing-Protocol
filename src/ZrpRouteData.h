// Connor Tamme, tammeconnor@gmail.com
//
//  Header file defining ZrpRouteData. This is metadata attached to ZRP routes used for IERP
//

#ifndef ZRP_ROUTE_DATA_H_
#define ZRP_ROUTE_DATA_H_

#include <vector>
#include <sstream>

#include "inet/networklayer/common/L3Address.h"

namespace inet {
namespace zrp {

enum ZrpRouteType { ZRP_ROUTE_IARP, ZRP_ROUTE_IERP };

// Metadata attached to ZRP routes in the routing table. Based on AODV.
// Has the full route path for IERP routes to allow maintenance and shortening.
class INET_API ZrpRouteData : public cObject {
  protected:
    ZrpRouteType routeType;

    // The full source route from source to destination, including endpoints.
    std::vector<L3Address> sourceRoute;

    // When this route was last confirmed/discovered
    simtime_t discoveryTime;

    // Whether this route is currently active (data can flow)
    bool active;

  public:
    ZrpRouteData(ZrpRouteType type = ZRP_ROUTE_IARP) : routeType(type), discoveryTime(SIMTIME_ZERO), active(true) {}

    virtual ~ZrpRouteData() {}

    ZrpRouteType getRouteType() const { return routeType; }
    void setRouteType(ZrpRouteType type) { this->routeType = type; }

    bool isIarpRoute() const { return routeType == ZRP_ROUTE_IARP; }
    bool isIerpRoute() const { return routeType == ZRP_ROUTE_IERP; }

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
        out << "type=" << (routeType == ZRP_ROUTE_IARP ? "IARP" : "IERP");
        out << ", active=" << (active ? "true" : "false");
        out << ", discovered=" << discoveryTime;

        if (routeType == ZRP_ROUTE_IERP && !sourceRoute.empty()) {
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

} // namespace zrp
} // namespace inet

#endif // ZRP_ROUTE_DATA_H_
