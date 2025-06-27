use libafl::{
    Error,
    monitors::{Monitor, stats::ClientStatsManager},
};
use libafl_bolts::ClientId;

#[derive(Clone, Debug, Default)]
pub struct GlobalMonitor {
    total_execs: u64,
    corpus_size: u64,
    objective_size: u64,

    pushover_creds: Option<(String, String)>,
}

pub fn send_pushover_notification(token: &str, user: &str, message: &str) {
    let params = [("token", token), ("user", user), ("message", message)];
    let client = reqwest::blocking::Client::new();
    if let Err(e) = client
        .post("https://api.pushover.net/1/messages.json")
        .form(&params)
        .send()
    {
        eprintln!("Failed to send pushover notification: {}", e);
    }
}

impl GlobalMonitor {
    pub fn with_pushover(token: String, user: String) -> Self {
        Self {
            pushover_creds: Some((token, user)),
            ..Default::default()
        }
    }
}

impl Monitor for GlobalMonitor {
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        event_msg: &str,
        sender_id: ClientId,
    ) {
        let trace = client_stats_manager
            .aggregated()
            .get("trace")
            .map_or("0%".to_string(), |c| c.to_string());
        let global_stats = client_stats_manager.global_stats();

        let event = match event_msg {
            "UserStats" => {
                let mut out = None;
                if global_stats.total_execs == 0
                    || global_stats.total_execs > self.total_execs
                    || global_stats.corpus_size > self.corpus_size
                {
                    self.total_execs = global_stats.total_execs.max(1);
                    self.corpus_size = global_stats.corpus_size;
                    out = Some("📊");
                }
                out
            }
            "Client Heartbeat" => Some("💗"),
            "Broker Heartbeat" => Some("💓"),
            "Objective" => {
                if let Some((token, user)) = self.pushover_creds.take() {
                    // Using `take()` ensures we only fire the notification once
                    send_pushover_notification(&token, &user, "🪲 Found a bug!");
                }

                let bugs = ["🪲", "🐛", "🐞", "🪰", "🦗", "🦋"];
                Some(bugs[global_stats.run_time.subsec_nanos() as usize % bugs.len()])
            }
            "Testcase" => None,
            _ => Some(event_msg),
        };

        if let Some(event) = event {
            println!(
                "{} time: {} (x{}) execs: {} cov: {} corpus: {} exec/sec: {} bugs: {}",
                event,
                global_stats.run_time_pretty,
                global_stats.client_stats_count,
                global_stats.total_execs,
                trace,
                global_stats.corpus_size,
                global_stats.execs_per_sec_pretty,
                global_stats.objective_size
            );
        }
    }
}
