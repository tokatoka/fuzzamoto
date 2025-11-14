#[cfg(feature = "bench")]
pub mod bench_stats;
#[cfg(feature = "bench")]
pub use bench_stats::*;

pub mod verify_timeouts;

pub use verify_timeouts::*;

use std::{borrow::Borrow, cell::RefCell, marker::PhantomData};

use fuzzamoto_ir::{Instruction, Minimizer, Operation};
use libafl::{
    Evaluator, ExecutesInput, HasMetadata,
    events::EventFirer,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::MapNoveltiesMetadata,
    inputs::Input,
    mutators::MutationResult,
    observers::{CanTrack, MapObserver, ObserversTuple},
    stages::{
        Restartable, Stage,
        mutational::{MutatedTransform, MutatedTransformPost},
    },
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::tuples::Handle;

use crate::input::IrInput;

pub struct ProbingStage {}

impl ProbingStage {
    pub fn new() -> Self {
        Self {}
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for ProbingStage
where
    E: Executor<EM, IrInput, S, Z>,
    Z: Evaluator<E, EM, IrInput, S>,
    S: HasMetadata + HasCorpus<IrInput> + HasCurrentTestcase<IrInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        let mut testcase = state.current_testcase_mut()?.clone();
        let Ok(mut input) = IrInput::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };

        // adding probing operation to the beginning and to the end of the instructions
        let mut builder = fuzzamoto_ir::ProgramBuilder::new(input.ir().context.clone());
        builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::EnableProbe,
            })
            .expect("appending EnableProbe should always succeed");
        builder
            .append_all(input.ir().instructions.iter().cloned())
            .expect("Partial append should always succeed if full append succeeded");
        builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::DisableProbe,
            })
            .expect("appending EnableProbe should always succeed");

        let Ok(new_program) = builder.finalize() else {
            return Ok(());
        };
        // now swap it with the new program
        *input.ir_mut() = new_program;
        let (untransformed, post) = input.try_transform_into(state)?;
        // this will automatically put metadata into the feedback
        log::info!("Doing Probing");
        let (_, corpus_id) = fuzzer.evaluate_filtered(state, executor, manager, &untransformed)?;
        post.post_exec(state, corpus_id)?;

        Ok(())
    }
}

impl<S> Restartable<S> for ProbingStage {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

pub struct IrMinimizerStage<'a, M, T, O> {
    trace_handle: Handle<T>,
    consecutive_failures: usize,
    max_consecutive_failures: usize,
    minimizing_crash: bool,
    keep_minimizing: &'a RefCell<u64>,
    _phantom: PhantomData<(M, O)>,
}

impl<'a, M, T, O> IrMinimizerStage<'a, M, T, O>
where
    O: MapObserver,
    T: AsRef<O> + CanTrack,
    M: Minimizer,
{
    pub fn new(
        trace_handle: Handle<T>,
        max_consecutive_failures: usize,
        minimizing_crash: bool,
        keep_minimizing: &'a RefCell<u64>,
    ) -> Self {
        Self {
            trace_handle,
            consecutive_failures: 0,
            max_consecutive_failures,
            minimizing_crash,
            keep_minimizing,
            _phantom: PhantomData,
        }
    }
}

// ?????
impl<'a, M, T, O, S> Restartable<S> for IrMinimizerStage<'a, M, T, O> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl<'a, M, E, EM, S, Z, OT, T, O> Stage<E, EM, S, Z> for IrMinimizerStage<'a, M, T, O>
where
    M: Minimizer,
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
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        if state.current_testcase()?.scheduled_count() > 0 {
            // Already minimized
            return Ok(());
        }

        let novelties = state
            .current_testcase()?
            .borrow()
            .metadata::<MapNoveltiesMetadata>()
            .map(|m| m.list.clone())
            .unwrap_or(vec![]);

        let mut success = false;
        let mut current_ir = state.current_input_cloned()?;

        log::info!(
            "{} reducing ir: {} instrs",
            std::any::type_name::<M>(),
            current_ir.ir().instructions.len()
        );
        let mut minimizer = M::new(current_ir.ir().clone());
        while let Some(prog) = minimizer.next() {
            if self.consecutive_failures > self.max_consecutive_failures {
                break;
            }

            if !prog.is_statically_valid() {
                log::info!(
                    "{} failure (not statically valid)",
                    std::any::type_name::<M>()
                );
                minimizer.failure();
                self.consecutive_failures += 1;
                continue;
            }

            let attempt = IrInput::new(prog);
            let Ok(exit_kind) = fuzzer.execute_input(state, executor, manager, &attempt) else {
                continue;
            };

            let number_of_retained_novelties = executor.observers()[&self.trace_handle]
                .as_ref()
                .how_many_set(&novelties);
            if (self.minimizing_crash && exit_kind != ExitKind::Ok)
                || (!self.minimizing_crash && number_of_retained_novelties == novelties.len())
            {
                // Minimization still has all the same novelties
                success = true;
                current_ir = attempt;
                minimizer.success();
                log::info!("{} success", std::any::type_name::<M>());
                self.consecutive_failures = 0;
            } else {
                minimizer.failure();
                log::info!("{} failure", std::any::type_name::<M>());
                self.consecutive_failures += 1;
            }
        }

        log::info!("{} done reducing", std::any::type_name::<M>(),);

        if success {
            *self.keep_minimizing.borrow_mut() += 1;
            current_ir.ir_mut().remove_nops();

            log::info!(
                "{} reduced ir to {} instructions",
                std::any::type_name::<M>(),
                current_ir.ir().instructions.len()
            );

            let mut testcase = state.current_testcase_mut()?;
            testcase.set_input(current_ir);
            let filepath = testcase.file_path().as_ref().unwrap().clone();
            log::info!(
                "{} reduced ir written to: {:?}",
                std::any::type_name::<M>(),
                filepath
            );
            let _ = testcase.input().as_ref().unwrap().to_file(filepath);
        }

        Ok(())
    }
}
