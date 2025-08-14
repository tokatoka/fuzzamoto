use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::Write,
    marker::PhantomData,
    path::PathBuf,
    time::{Duration, Instant},
};

use libafl::{
    Evaluator, ExecutesInput, HasMetadata,
    events::EventFirer,
    executors::{Executor, HasObservers},
    observers::{CanTrack, MapObserver, ObserversTuple},
    stages::{Restartable, Stage},
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::tuples::Handle;

use crate::input::IrInput;

/// Stage for collecting fuzzer stats useful for benchmarking
pub struct BenchStatsStage<T, O> {
    trace_handle: Handle<T>,

    last_coverage: HashSet<usize>,

    initialised: Instant,
    last_update: Instant,
    update_interval: Duration,

    stats_file_path: PathBuf,
    csv_header_written: bool,

    _phantom: PhantomData<O>,
}

impl<T, O> BenchStatsStage<T, O> {
    pub fn new(
        trace_handle: Handle<T>,
        update_interval: Duration,
        stats_file_path: PathBuf,
    ) -> Self {
        let last_update = Instant::now() - 2 * update_interval;
        Self {
            trace_handle,
            last_coverage: HashSet::new(),
            initialised: Instant::now(),
            last_update,
            update_interval,
            stats_file_path,
            csv_header_written: false,
            _phantom: PhantomData::default(),
        }
    }
}

impl<T, O, S> Restartable<S> for BenchStatsStage<T, O> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl<E, EM, S, Z, OT, T, O> Stage<E, EM, S, Z> for BenchStatsStage<T, O>
where
    S: HasCorpus<IrInput> + HasCurrentTestcase<IrInput> + HasMetadata,
    E: Executor<EM, IrInput, S, Z> + HasObservers<Observers = OT>,
    EM: EventFirer<IrInput, S>,
    Z: Evaluator<E, EM, IrInput, S> + ExecutesInput<E, EM, IrInput, S>,
    OT: ObserversTuple<IrInput, S>,
    O: MapObserver,
    T: CanTrack + AsRef<O>,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut E,
        _state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        let now = Instant::now();
        if now < self.last_update + self.update_interval {
            return Ok(());
        }
        // Only dump new stats every `self.update_interval`
        self.last_update = now;

        let observers = executor.observers();
        let map_observer = observers[&self.trace_handle].as_ref();
        let initial_entry_value = map_observer.initial();

        let mut new_coverage = Vec::new();
        for i in 0..map_observer.len() {
            if map_observer.get(i) != initial_entry_value {
                if self.last_coverage.insert(i) {
                    new_coverage.push(i);
                }
            }
        }

        // Write the new coverage indices to the stats file as CSV
        if !new_coverage.is_empty() {
            // We need to store the path temporarily since we can't borrow self while calling ensure_file_open
            let _ = std::fs::create_dir_all(self.stats_file_path.parent().unwrap());
            let stats_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.stats_file_path)
                .map_err(|e| libafl::Error::unknown(format!("Failed to open stats file: {}", e)))?;

            // Write CSV header if this is the first time
            if !self.csv_header_written {
                writeln!(&stats_file, "timestamp,new_coverage_indices").map_err(|e| {
                    libafl::Error::unknown(format!("Failed to write CSV header: {}", e))
                })?;
                self.csv_header_written = true;
            }

            // Write new coverage data
            let timestamp = now.duration_since(self.initialised).as_secs();
            let coverage_str = new_coverage
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(";");
            writeln!(&stats_file, "{},{}", timestamp, coverage_str)
                .map_err(|e| libafl::Error::unknown(format!("Failed to write CSV data: {}", e)))?;
        }

        Ok(())
    }
}
