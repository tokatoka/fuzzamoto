use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum IRCommands {
    /// Generate fuzzamoto IR
    Generate {
        #[arg(long, help = "Path to the output directory for the generated IR")]
        output: PathBuf,
        #[arg(
            long,
            help = "Max number of iterations to generate each output IR program for"
        )]
        iterations: usize,
        #[arg(long, help = "Number of IR programs to generate")]
        programs: usize,
        #[arg(long, help = "Path to the program context file")]
        context: PathBuf,
    },
    /// Compile fuzzamoto IR
    Compile {
        #[arg(long, help = "Path to the input file/directory for the generated IR")]
        input: PathBuf,
        #[arg(long, help = "Path to the output file/directory for the compiled IR")]
        output: PathBuf,
    },

    /// Convert fuzzamoto corpora
    Convert {
        #[arg(long, help = "Format of the input IR", value_enum, default_value_t = CorpusFormat::Postcard)]
        from: CorpusFormat,
        #[arg(long, help = "Format of the output IR", value_enum, default_value_t = CorpusFormat::Json)]
        to: CorpusFormat,
        #[arg(long, help = "Path to the input file/directory for the generated IR")]
        input: PathBuf,
        #[arg(long, help = "Path to the output file/directory for the converted IR")]
        output: PathBuf,
    },

    /// Print human readable IR
    Print {
        #[arg(long, help = "Print IR in json format", default_value_t = false)]
        json: bool,

        #[arg(help = "Path to the input IR file ot be displayed")]
        input: PathBuf,
    },

    /// Analyze IR corpus statistics
    Analyze {
        #[arg(help = "Path to the input IR directory to analyze")]
        input: PathBuf,
    },
}

#[derive(ValueEnum, Debug, Clone)]
pub enum CorpusFormat {
    Json,
    Postcard, // Default corpus format (https://github.com/jamesmunns/postcard)
}
