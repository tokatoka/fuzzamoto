use crate::{connections::Connection, targets::Target};

/// `ScenarioCharacterization` is a trait for characterizing the behavior of a scenario.
pub trait ScenarioCharacterization {
    /// Reduce the result to a 32 byte array (e.g. a hash of the result).
    fn reduce(&self) -> [u8; 32];
}

/// `IgnoredCharacterization` is a type of scenario characterization that is ignored by the fuzzer.
/// Used for scenarios that are not meant to characterize behavior.
pub struct IgnoredCharacterization;
impl ScenarioCharacterization for IgnoredCharacterization {
    fn reduce(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

/// `ScenarioInput` is a trait for scenario input types.
pub trait ScenarioInput: Sized {
    /// Decode the input from a byte slice.
    fn decode(bytes: &[u8]) -> Result<Self, String>;
}

/// `ScenarioResult` describes the various outcomes of running a scenario.
pub enum ScenarioResult<SC: ScenarioCharacterization> {
    /// Scenario ran successfully and the behavior characterization is returned.
    Ok(SC),
    /// Scenario indicated that the test case should be skipped.
    Skip,
    /// Scenario indicated that the test case failed (i.e. the target node crashed).
    Fail(String),
}

/// `Scenario` is the interface for test scenarios that can be run against a target node.
pub trait Scenario<I, SC, C, T>: Sized
where
    I: ScenarioInput,
    SC: ScenarioCharacterization,
    C: Connection,
    T: Target<C>,
{
    // Create a new instance of the scenario, preparing the initial state of the test
    fn new(target: T) -> Result<Self, String>;
    // Run the test
    fn run(&mut self, testcase: I) -> ScenarioResult<SC>;
}

#[macro_export]
macro_rules! fuzzamoto_main {
    ($scenario_type:ty, $target_type:ty, $testcase_type:ty) => {
        fn main() {
            use env_logger;
            env_logger::init();

            let args: Vec<String> = std::env::args().collect();
            if args.len() < 2 {
                eprintln!("Usage: {} <bitcoin-core-exe-path>", args[0]);
                std::process::exit(1);
            }

            let runner = fuzzamoto::runners::StdRunner::new();

            log::info!("Starting target...");
            let exe_path = &args[1];
            let target = <$target_type>::new(exe_path).unwrap();

            log::info!("Initializing scenario...");
            let mut scenario = <$scenario_type>::new(target).unwrap();

            // Ensure the runner dropped prior to the target and scenario when returning from main.
            let runner = runner;
            log::info!("Scenario initialized! Running input...");

            // In nyx mode the snapshot is taken here and a new fuzz input is provided each reset.
            let input = runner.get_fuzz_input();

            let Ok(testcase) = <$testcase_type>::decode(&input) else {
                log::warn!("Failed to decode test case!");
                drop(scenario);
                runner.skip();
                return;
            };

            match scenario.run(testcase) {
                ScenarioResult::Ok(_) => {}
                ScenarioResult::Skip => {
                    drop(scenario);
                    runner.skip();
                    return;
                }
                ScenarioResult::Fail(err) => {
                    runner.fail(&format!("Test case failed: {}", err));
                    return;
                }
            }

            log::info!("Test case ran successfully!");
        }
    };
}
