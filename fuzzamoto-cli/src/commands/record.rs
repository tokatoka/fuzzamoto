use crate::error::Result;
use crate::utils::{file_ops, process};
use std::path::PathBuf;

pub struct RecordCommand;

impl RecordCommand {
    pub fn execute(output: PathBuf, corpus: PathBuf, scenario: PathBuf) -> Result<()> {
        file_ops::ensure_file_exists(&scenario)?;

        let corpus_files = file_ops::read_dir_files(&corpus)?;

        // Record each corpus file
        for corpus_file in corpus_files {
            let output_file = output.join(format!(
                "{}.recording.bin",
                corpus_file.file_name().unwrap().to_str().unwrap()
            ));

            if let Err(e) = Self::record_one_input(&corpus_file, &output_file, &scenario) {
                log::error!("Failed to record input ({:?}): {}", corpus_file, e);
            }
        }

        log::info!(
            "Recording completed. Output directory: {}",
            output.display()
        );

        Ok(())
    }

    fn record_one_input(input: &PathBuf, output: &PathBuf, scenario: &PathBuf) -> Result<()> {
        log::info!("Recording input: {}", input.display());

        let env_vars = vec![
            ("FUZZAMOTO_RECORD_FILE", output.to_str().unwrap()),
            ("FUZZAMOTO_INPUT", input.to_str().unwrap()),
            ("RUST_LOG", "debug"),
        ];

        // Use a dummy bitcoind path since we're just recording
        let dummy_bitcoind = PathBuf::from("./foobar");

        process::run_scenario_command(scenario, &dummy_bitcoind, &env_vars)?;

        Ok(())
    }
}
