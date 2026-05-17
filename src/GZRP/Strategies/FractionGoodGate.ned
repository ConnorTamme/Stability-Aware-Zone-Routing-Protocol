package sa_zrp.GZRP.Strategies;

simple FractionGoodGate like IGateStrategy
{
    parameters:
        @class("inet::gzrp::FractionGoodGate");
        @display("i=block/cogwheel");
        double q = default(0.5);   // Minimum fraction of neighbours with quality >= tau
}
