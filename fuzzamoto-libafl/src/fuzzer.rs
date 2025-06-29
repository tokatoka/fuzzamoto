use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{self, Write},
};

use clap::Parser;
#[cfg(feature = "simplemgr")]
use libafl::events::SimpleEventManager;
use libafl::{
    Error,
    events::{
        ClientDescription, EventConfig, Launcher, LlmpEventManagerBuilder, MonitorTypedEventManager,
    },
    monitors::{Monitor, tui::TuiMonitor},
};

use libafl_bolts::{
    core_affinity::CoreId,
    current_time,
    llmp::LlmpBroker,
    shmem::{ShMemProvider, StdShMemProvider},
    staterestore::StateRestorer,
    tuples::tuple_list,
};
#[cfg(unix)]
use {
    nix::unistd::dup,
    std::os::unix::io::{AsRawFd, FromRawFd},
};

use crate::{
    client::Client,
    monitor::{self, GlobalMonitor},
    options::FuzzerOptions,
};

pub struct Fuzzer {
    options: FuzzerOptions,
}

impl Fuzzer {
    pub fn new() -> Fuzzer {
        let options = FuzzerOptions::parse();
        Fuzzer { options }
    }

    pub fn fuzz(&self) -> Result<(), Error> {
        if self.options.tui {
            let monitor = TuiMonitor::builder()
                .title("Fuzzamoto IR Fuzzer")
                .version("0.1.0")
                .enhanced_graphics(true)
                .build();
            self.launch(monitor)
        } else {
            let log = self.options.log.as_ref().and_then(|l| {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(l)
                    .ok()
                    .map(RefCell::new)
            });

            #[cfg(unix)]
            let stdout_cpy = RefCell::new(unsafe {
                let new_fd = dup(io::stdout().as_raw_fd()).unwrap();
                File::from_raw_fd(new_fd)
            });

            // The stats reporter for the broker
            let monitor = if let (Some(token), Some(user)) = (
                self.options.pushover_token.clone(),
                self.options.pushover_user.clone(),
            ) {
                println!("Using pushover notifications, will notify on first bug found");
                monitor::send_pushover_notification(&token, &user, "✅ New campaign has begun");
                GlobalMonitor::with_pushover(token, user)
            } else {
                GlobalMonitor::default()
            };
            self.launch(monitor)
        }
    }

    fn launch<M>(&self, monitor: M) -> Result<(), Error>
    where
        M: Monitor + Clone,
    {
        // The shared memory allocator
        let mut shmem_provider = StdShMemProvider::new()?;

        /* If we are running in verbose, don't provide a replacement stdout, otherwise, use /dev/null */
        let stdout = if self.options.verbose {
            None
        } else {
            Some("/dev/null")
        };

        let client = Client::new(&self.options);

        #[cfg(not(feature = "simplemgr"))]
        if self.options.rerun_input.is_some() || self.options.minimize_input.is_some() {
            // If we want to rerun a single input but we use a restarting mgr, we'll have to create
            // a fake restarting mgr that doesn't actually restart. It's not pretty but better than
            // recompiling with simplemgr.

            // Just a random number, let's hope it's free :)
            let broker_port = 13120;
            let _fake_broker = LlmpBroker::create_attach_to_tcp(
                shmem_provider.clone(),
                tuple_list!(),
                broker_port,
            )
            .unwrap();

            // To rerun an input, instead of using a launcher, we create dummy parameters and run
            // the client directly.
            return client.run(
                None,
                MonitorTypedEventManager::<_, M>::new(
                    LlmpEventManagerBuilder::builder().build_on_port(
                        shmem_provider.clone(),
                        broker_port,
                        EventConfig::AlwaysUnique,
                        Some(StateRestorer::new(
                            shmem_provider.new_shmem(0x1000).unwrap(),
                        )),
                    )?,
                ),
                ClientDescription::new(0, 0, CoreId(0)),
            );
        }

        #[cfg(feature = "simplemgr")]
        return client.run(
            None,
            SimpleEventManager::new(monitor),
            ClientDescription::new(0, 0, CoreId(0)),
        );

        // Build and run a Launcher
        #[cfg(not(feature = "simplemgr"))]
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(self.options.port)
            .configuration(EventConfig::from_build_id())
            // If starting with an existing corpus and many clients, crashes in the llmp broker
            // have been observed. Unclear what's happening, but an increased launch delay or fewer
            // clients mitigate the issue.
            .launch_delay(self.options.launch_delay)
            .monitor(monitor)
            .run_client(|s, m, c| client.run(s, MonitorTypedEventManager::<_, M>::new(m), c))
            .cores(&self.options.cores)
            .stdout_file(stdout)
            .stderr_file(stdout)
            .build()
            .launch()
        {
            Ok(()) => Ok(()),
            Err(Error::ShuttingDown) => {
                println!("Fuzzing stopped by user. Good bye.");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}
