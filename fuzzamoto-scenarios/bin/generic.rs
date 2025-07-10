use fuzzamoto::{
    fuzzamoto_main,
    scenarios::{
        Scenario, ScenarioInput, ScenarioResult,
        generic::{GenericScenario, TestCase},
    },
    targets::BitcoinCoreTarget,
};

fuzzamoto_main!(
    GenericScenario::<fuzzamoto::connections::V1Transport, BitcoinCoreTarget>,
    TestCase
);
