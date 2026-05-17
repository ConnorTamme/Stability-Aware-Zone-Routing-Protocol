package sa_zrp.GZRP.Strategies;

simple LparStabilityScore like IScoringStrategy
{
    parameters:
        @class("inet::gzrp::LparStabilityScore");
        @display("i=block/cogwheel");
        double commsRange @unit(m);             // Transmission range R (required, scenario dependent)
        double vMax @unit(mps);                 // Maximum UAV speed (required, scenario dependent)
        double distanceExponent = default(4);   // Exponent p in D = 1 - (d/R)^p
}
