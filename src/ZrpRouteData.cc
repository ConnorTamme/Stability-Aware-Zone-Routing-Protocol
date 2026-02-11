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

#include "ZrpRouteData.h"

// ZrpRouteData is currently header-only (all methods are inline).
// This .cc file exists for future extensions and to ensure the class
// is compiled and linked into the binary.

namespace inet {
namespace zrp {

// Register with OMNeT++ so it can be displayed in the GUI
Register_Class(ZrpRouteData);

} // namespace zrp
} // namespace inet
