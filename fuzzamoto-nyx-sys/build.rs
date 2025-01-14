fn main() {
    if let Ok(bitcoind_path) = std::env::var("BITCOIND_PATH") {
        // Execute bitcoind with -help and AFL_DEBUG environment variable
        let output = std::process::Command::new(bitcoind_path)
            .env("AFL_DUMP_MAP_SIZE", "1")
            .output()
            .expect("Failed to execute bitcoind");

        // Convert the output to a string
        let output_str = String::from_utf8_lossy(&output.stdout);

        // Build the agent with the parsed AFL_MAP_SIZE
        cc::Build::new()
            .file("src/nyx-agent.c")
            .define("NO_PT_NYX", None)
            .define("MAP_SIZE", &*output_str.trim())
            .compile("nyx_agent");
    } else {
        // Build the agent without defining MAP_SIZE
        cc::Build::new()
            .file("src/nyx-agent.c")
            .define("NO_PT_NYX", None)
            .compile("nyx_agent");
    }

    println!("cargo:rerun-if-changed=src/nyx-agent.c");
    println!("cargo:rerun-if-env-changed=BITCOIND_PATH");
}
