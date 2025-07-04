use crate::{
    connections::Transport,
    targets::{ConnectableTarget, HasTipHash, Target},
};
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};

pub enum OracleResult {
    Pass,
    Fail(String),
}

pub trait Oracle<C> {
    fn evaluate(&self, context: &C) -> OracleResult;
    fn name(&self) -> &str;
}

/// `CrashOracle` checks if a given target is still alive
pub struct CrashOracle<TX>(PhantomData<TX>);

impl<TX> Default for CrashOracle<TX> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T, TX> Oracle<T> for CrashOracle<TX>
where
    TX: Transport,
    T: Target<TX>,
{
    fn evaluate(&self, target: &T) -> OracleResult {
        match target.is_alive() {
            Ok(_) => OracleResult::Pass,
            Err(err) => OracleResult::Fail(format!("Target is not alive: {}", err)),
        }
    }

    fn name(&self) -> &str {
        "CrashOracle"
    }
}

/// `ConsensusContext` is the context for the `ConsensusOracle`
pub struct ConsensusContext<'a, T1, T2> {
    pub primary: &'a T1,
    pub reference: &'a T2,
    pub consensus_timeout: Duration,
    pub poll_interval: Duration,
}

/// `ConsensusOracle` checks if two full node targets reach consensus on the chain tip hash
pub struct ConsensusOracle<TX1, TX2>(PhantomData<TX1>, PhantomData<TX2>);

impl<TX1, TX2> Default for ConsensusOracle<TX1, TX2> {
    fn default() -> Self {
        Self(PhantomData, PhantomData)
    }
}

impl<'a, T1, T2, TX1, TX2> Oracle<ConsensusContext<'a, T1, T2>> for ConsensusOracle<TX1, TX2>
where
    TX1: Transport,
    TX2: Transport,
    T1: Target<TX1> + HasTipHash,
    T2: Target<TX2> + HasTipHash,
{
    fn evaluate(&self, context: &ConsensusContext<'a, T1, T2>) -> OracleResult {
        let start = Instant::now();

        let mut primary_tip = None;
        let mut reference_tip = None;

        while start.elapsed() < context.consensus_timeout {
            primary_tip = context.primary.get_tip_hash();
            reference_tip = context.reference.get_tip_hash();

            if primary_tip.is_some() && primary_tip == reference_tip {
                // Consensus is reached if tips match and are not None.
                return OracleResult::Pass;
            }

            std::thread::sleep(context.poll_interval);
        }

        OracleResult::Fail(format!(
            "Nodes did not reach consensus within {:?}. Primary: {primary_tip:?}, Reference: {reference_tip:?}",
            context.consensus_timeout
        ))
    }

    fn name(&self) -> &str {
        "ConsensusOracle"
    }
}

pub struct NetSplitContext<'a, T1, T2> {
    pub primary: &'a T1,
    pub reference: &'a T2,
}

/// `NetSplitOracle` checks if two full node targets are connected
pub struct NetSplitOracle<TX1, TX2>(PhantomData<TX1>, PhantomData<TX2>);

impl<TX1, TX2> Default for NetSplitOracle<TX1, TX2> {
    fn default() -> Self {
        Self(PhantomData, PhantomData)
    }
}

impl<'a, T1, T2, TX1, TX2> Oracle<NetSplitContext<'a, T1, T2>> for NetSplitOracle<TX1, TX2>
where
    TX1: Transport,
    TX2: Transport,
    T1: Target<TX1> + ConnectableTarget,
    T2: Target<TX2> + ConnectableTarget,
{
    fn evaluate(&self, context: &NetSplitContext<'a, T1, T2>) -> OracleResult {
        match context.reference.is_connected_to(context.primary) {
            false => OracleResult::Fail("Nodes are no longer connected!".to_string()),
            true => OracleResult::Pass,
        }
    }

    fn name(&self) -> &str {
        "NetSplitOracle"
    }
}
