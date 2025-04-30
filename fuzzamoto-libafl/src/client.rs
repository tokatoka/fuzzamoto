use libafl::{
    Error,
    corpus::{CachedOnDiskCorpus, OnDiskCorpus},
    events::ClientDescription,
    monitors::Monitor,
    state::StdState,
};
use libafl_bolts::rands::StdRand;

use crate::{
    input::IrInput,
    instance::{ClientMgr, Instance},
    options::FuzzerOptions,
};

#[allow(clippy::module_name_repetitions)]
pub type ClientState =
    StdState<CachedOnDiskCorpus<IrInput>, IrInput, StdRand, OnDiskCorpus<IrInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl Client<'_> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    pub fn run<M: Monitor>(
        &self,
        state: Option<ClientState>,
        mgr: ClientMgr<M>,
        client_description: ClientDescription,
    ) -> Result<(), Error> {
        let instance = Instance::builder()
            .options(self.options)
            .mgr(mgr)
            .client_description(client_description);

        instance.build().run(state)
    }
}
