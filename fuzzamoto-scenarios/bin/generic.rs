use fuzzamoto::{
    fuzzamoto_main,
    runners::Runner,
    scenarios::{
        generic::{GenericScenario, TestCase},
        Scenario, ScenarioInput, ScenarioResult,
    },
    targets::BitcoinCoreTarget,
};

fuzzamoto_main!(GenericScenario, BitcoinCoreTarget, TestCase);
