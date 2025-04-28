use fuzzamoto::{
    fuzzamoto_main,
    scenarios::{
        Scenario, ScenarioInput, ScenarioResult,
        generic::{GenericScenario, TestCase},
    },
    targets::BitcoinCoreTarget,
};

#[cfg(feature = "record")]
fn main() {
    panic!("Generic scenario can't be recorded");
}

#[cfg(not(feature = "record"))]
fuzzamoto_main!(
    GenericScenario::<fuzzamoto::connections::V1Transport, BitcoinCoreTarget>,
    TestCase
);
