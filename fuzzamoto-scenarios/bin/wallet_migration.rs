use fuzzamoto::{
    connections::{RecordingTransport, Transport, V1Transport},
    fuzzamoto_main,
    runners::Runner,
    scenarios::{
        IgnoredCharacterization, Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario,
    },
    targets::{BitcoinCoreTarget, RecorderTarget, Target},
};

use std::io::Write;
use std::path::PathBuf;

struct WalletDotDatBytes<'a>(&'a [u8]);

impl<'a> ScenarioInput<'a> for WalletDotDatBytes<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        Ok(WalletDotDatBytes(bytes))
    }
}

/// `WalletMigrationScenario` is a scenario that tests Bitcoin Core's `migratewallet` RPC command.
///
/// Testcases represent wallet.dat files to be migrated. All the scenario does is place the given
/// wallet.dat file in the default wallet directory and call the `migratewallet` RPC command.
struct WalletMigrationScenario<TX: Transport, T: Target<TX>> {
    _inner: GenericScenario<TX, T>,
    wallet_path: PathBuf,
}

impl<'a>
    Scenario<'a, WalletDotDatBytes<'a>, IgnoredCharacterization, V1Transport, BitcoinCoreTarget>
    for WalletMigrationScenario<V1Transport, BitcoinCoreTarget>
{
    fn new(target: &mut BitcoinCoreTarget) -> Result<Self, String> {
        let inner = GenericScenario::new(target)?;

        let _ = target
            .node
            .client
            .call::<serde_json::Value>("unloadwallet", &["default".into()]);
        let wallet_path = target
            .node
            .workdir()
            .join("regtest")
            .join("wallets")
            .join("default");
        let _ = std::fs::remove_dir_all(&wallet_path);

        Ok(Self {
            _inner: inner,
            wallet_path: wallet_path.join("wallet.dat"),
        })
    }

    fn run(
        &mut self,
        target: &mut BitcoinCoreTarget,
        input: WalletDotDatBytes,
    ) -> ScenarioResult<IgnoredCharacterization> {
        let _ = std::fs::create_dir_all(self.wallet_path.parent().unwrap());

        if let Ok(mut wallet_file) = std::fs::File::create(&self.wallet_path) {
            let _ = wallet_file.write_all(&input.0);
            let _ = wallet_file.flush();

            let _ = target
                .node
                .client
                .call::<serde_json::Value>("migratewallet", &["default".into()]);
        }

        if let Err(e) = target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {}", e));
        }

        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

// `WalletMigrationScenario` is specific to the `BitcoinCoreTarget` and does not allow for recording.
// This specialisation is a nop scenario for recording.
impl<'a>
    Scenario<
        'a,
        WalletDotDatBytes<'a>,
        IgnoredCharacterization,
        RecordingTransport,
        RecorderTarget<BitcoinCoreTarget>,
    > for WalletMigrationScenario<RecordingTransport, RecorderTarget<BitcoinCoreTarget>>
{
    fn new(target: &mut RecorderTarget<BitcoinCoreTarget>) -> Result<Self, String> {
        let inner = GenericScenario::new(target)?;

        Ok(Self {
            _inner: inner,
            wallet_path: PathBuf::new(),
        })
    }

    fn run(
        &mut self,
        _target: &mut RecorderTarget<BitcoinCoreTarget>,
        _input: WalletDotDatBytes,
    ) -> ScenarioResult<IgnoredCharacterization> {
        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

fuzzamoto_main!(
    WalletMigrationScenario,
    BitcoinCoreTarget,
    WalletDotDatBytes
);
