//
// Module interfaces for the four logical decisions GZRP delegates to
// swappable submodules. A concrete strategy must declare itself `like` one
// of these interfaces; Gzrp then check_and_casts the submodule to the
// matching C++ interface declared in IStrategy.h.
//

package sa_zrp.GZRP.Strategies;

moduleinterface IScoringStrategy { parameters: @display("i=block/cogwheel"); }
moduleinterface IDecayStrategy     { parameters: @display("i=block/cogwheel"); }
moduleinterface IGateStrategy      { parameters: @display("i=block/cogwheel"); }
moduleinterface IThresholdStrategy { parameters: @display("i=block/cogwheel"); }
