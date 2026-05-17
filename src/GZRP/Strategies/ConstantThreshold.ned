package sa_zrp.GZRP.Strategies;

simple ConstantThreshold like IThresholdStrategy
{
    parameters:
        @class("inet::gzrp::ConstantThreshold");
        @display("i=block/cogwheel");
        double value = default(0.3);
}
