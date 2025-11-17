use crate::input::IrInput;
use libafl::{
    HasMetadata,
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    observers::StdOutObserver,
    state::HasCorpus,
};
use libafl_bolts::Error;
use libafl_bolts::Named;
use std::borrow::Cow;

use libafl_bolts::tuples::{Handle, Handled, MatchName, MatchNameRef};
/// Module to parse the message sent from the other node
#[derive(Clone, Debug)]
pub struct RecvFeedback {
    o_ref: Handle<StdOutObserver>,
}

impl RecvFeedback {
    /// Creates a new [`RecvFeedback`].
    #[must_use]
    pub fn new(observer: &StdOutObserver) -> Self {
        Self {
            o_ref: observer.handle(),
        }
    }
}

impl Named for RecvFeedback {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("RecvFeedback");
        &NAME
    }
}

impl<S> StateInitializer<S> for RecvFeedback {}

impl<EM, OT, S> Feedback<EM, IrInput, OT, S> for RecvFeedback
where
    S: HasCorpus<IrInput> + HasMetadata,
    OT: MatchName,
{
    #[inline]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &IrInput,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let observer = observers
            .get(&self.o_ref)
            .ok_or(Error::illegal_state("StdOutObserver is missing"))?;

        let buffer = observer
            .output
            .as_ref()
            .ok_or(Error::illegal_state("StdOutObserver has no stdout"))?;
        if !buffer.is_empty() {
            let chunks: Vec<Vec<u8>> = buffer
                .split(|b| *b == b'\n')
                .map(|slice| slice.to_vec())
                .collect();

            for chunk in chunks {
                if chunk.is_empty() {
                    continue;
                }
                if let Ok((conn, command, payload)) =
                    serde_json::from_slice::<(usize, String, Vec<u8>)>(&chunk)
                {
                    log::info!(
                        "Command received. From {:?}, command: {:?}, payload: {:?}",
                        conn,
                        command,
                        payload
                    );
                } else {
                    // for some reason, I cannot receive more than 2686 bytes... (limitation from nyx side?)
                    // but the target does send us more bytes than that, in that case just print into the log
                    log::info!("Failed to deserialize payload (size: {})", chunk.len());
                }
            }
        }
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<IrInput>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
