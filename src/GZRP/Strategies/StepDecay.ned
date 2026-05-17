package sa_zrp.GZRP.Strategies;

simple StepDecay like IDecayStrategy
{
    parameters:
        @class("inet::gzrp::StepDecay");
        @display("i=block/cogwheel");
        int radius = default(2);   // Zone radius in hops (classic ZRP k)
}
