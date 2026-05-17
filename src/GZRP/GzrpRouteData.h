//
//  Header file defining GzrpRouteData. This is metadata attached to GZRP
//  routes used for IERP. Mirrors the SAZRP layout.
//

#ifndef GZRPROUTEDATA_H_
#define GZRPROUTEDATA_H_

#include <vector>
#include <sstream>

#include "inet/networklayer/common/L3Address.h"

namespace inet {
namespace gzrp {

enum GzrpRouteType { GZRP_ROUTE_IARP, GZRP_ROUTE_IERP };

class INET_API GzrpRouteData : public cObject {
  protected:
    GzrpRouteType routeType;
    std::vector<L3Address> sourceRoute;
    simtime_t discoveryTime;
    bool active;

  public:
    GzrpRouteData(GzrpRouteType type = GZRP_ROUTE_IARP) : routeType(type), discoveryTime(SIMTIME_ZERO), active(true) {}

    virtual ~GzrpRouteData() {}

    GzrpRouteType getRouteType() const { return routeType; }
    void setRouteType(GzrpRouteType type) { this->routeType = type; }

    bool isIarpRoute() const { return routeType == GZRP_ROUTE_IARP; }
    bool isIerpRoute() const { return routeType == GZRP_ROUTE_IERP; }

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
        out << "type=" << (routeType == GZRP_ROUTE_IARP ? "IARP" : "IERP");
        out << ", active=" << (active ? "true" : "false");
        out << ", discovered=" << discoveryTime;

        if (routeType == GZRP_ROUTE_IERP && !sourceRoute.empty()) {
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

} // namespace gzrp
} // namespace inet

#endif // GZRPROUTEDATA_H_
