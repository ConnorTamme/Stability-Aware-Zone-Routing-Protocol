//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#ifndef ZRP_ROUTE_DATA_H_
#define ZRP_ROUTE_DATA_H_

#include <vector>
#include <sstream>

#include "inet/networklayer/common/L3Address.h"

using namespace inet;

namespace zrp {

// Identifies which ZRP sub-protocol owns a given route
enum ZrpRouteType {
    ZRP_ROUTE_IARP,   // Proactive intrazone route (computed by Dijkstra on link state)
    ZRP_ROUTE_IERP    // Reactive interzone route (discovered by query/reply)
};

/**
 * ZrpRouteData is attached to IRoute entries created by ZRP.
 * It stores the route type and, for IERP routes, the full source route
 * path so we can do route maintenance (shortening, repair) per the RFC.
 *
 * This is analogous to AODV's AodvRouteData which stores sequence numbers
 * and precursor lists.
 */
class INET_API ZrpRouteData : public cObject
{
  protected:
    ZrpRouteType routeType;

    // --- IERP-specific fields ---
    // The full source route from source to destination, including endpoints.
    // e.g., [A, B, C, D] means A->B->C->D
    std::vector<L3Address> sourceRoute;

    // When this route was last confirmed/discovered
    simtime_t discoveryTime;

    // Whether this route is currently active (data can flow)
    bool active;

  public:
    ZrpRouteData(ZrpRouteType type = ZRP_ROUTE_IARP)
        : routeType(type), discoveryTime(SIMTIME_ZERO), active(true) {}

    virtual ~ZrpRouteData() {}

    // --- Route type ---
    ZrpRouteType getRouteType() const { return routeType; }
    void setRouteType(ZrpRouteType type) { this->routeType = type; }

    bool isIarpRoute() const { return routeType == ZRP_ROUTE_IARP; }
    bool isIerpRoute() const { return routeType == ZRP_ROUTE_IERP; }

    // --- Source route (IERP) ---
    const std::vector<L3Address>& getSourceRoute() const { return sourceRoute; }
    void setSourceRoute(const std::vector<L3Address>& route) { this->sourceRoute = route; }

    size_t getSourceRouteLength() const { return sourceRoute.size(); }

    // --- Discovery time ---
    const simtime_t& getDiscoveryTime() const { return discoveryTime; }
    void setDiscoveryTime(const simtime_t& t) { this->discoveryTime = t; }

    // --- Active state ---
    bool isActive() const { return active; }
    void setIsActive(bool a) { this->active = a; }

    // --- Display ---
    virtual std::string str() const override
    {
        std::ostringstream out;
        out << "type=" << (routeType == ZRP_ROUTE_IARP ? "IARP" : "IERP");
        out << ", active=" << (active ? "true" : "false");
        out << ", discovered=" << discoveryTime;

        if (routeType == ZRP_ROUTE_IERP && !sourceRoute.empty()) {
            out << ", route=[";
            for (size_t i = 0; i < sourceRoute.size(); i++) {
                if (i > 0) out << " -> ";
                out << sourceRoute[i];
            }
            out << "]";
        }

        return out.str();
    }
};

} // namespace zrp

#endif // ZRP_ROUTE_DATA_H_
