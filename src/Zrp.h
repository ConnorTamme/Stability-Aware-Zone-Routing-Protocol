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

#ifndef ZRP_H_
#define ZRP_H_

#define IARP_METRIC_COUNT 1

class Zrp: public inet::RoutingProtocolBase {
protected:
    //parameters
    simtime_t linkStateLifetime = 3;
    simtime_t helloInterval = 3;
    unsigned int zoneRadius = 2;

protected:
    void handleMessageWhenUp(cMessage * msg) override;
    void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

    //IARP Functions
    void IARP_Deliver(cMessage)
public:
    Zrp();
    virtual ~Zrp();
};

#endif /* ZRP_H_ */
