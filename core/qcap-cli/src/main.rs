use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "qcap", version, about = "Q-Cap CLI (alpha)")]
struct Cli { #[command(subcommand)] command: Commands }

#[derive(Subcommand)]
enum Commands {
    /// Demo: hash input bytes
    Hash { input: String },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hash { input } => {
            let root = qcap_core::merkle_root_demo(input.as_bytes());
            println!("{}", root);
        }
    }
}
