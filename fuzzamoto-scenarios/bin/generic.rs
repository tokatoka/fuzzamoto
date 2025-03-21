use fuzzamoto::{
    fuzzamoto_main,
    runners::Runner,
    scenarios::{
        Scenario, ScenarioInput, ScenarioResult,
        generic::{GenericScenario, TestCase},
    },
    targets::BitcoinCoreTarget,
};

fuzzamoto_main!(GenericScenario, BitcoinCoreTarget, TestCase);
