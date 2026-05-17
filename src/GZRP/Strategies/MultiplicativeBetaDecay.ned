package sa_zrp.GZRP.Strategies;

simple MultiplicativeBetaDecay like IDecayStrategy
{
    parameters:
        @class("inet::gzrp::MultiplicativeBetaDecay");
        @display("i=block/cogwheel");
        double betaMin = default(0.7);
        double betaMax = default(0.85);
}
