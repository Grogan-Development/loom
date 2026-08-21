//! Standalone insights harness: diff + rust/go/ts-ish symbol extractor.
//!
//! Usable on a materialized tree pair (Grid runner or local checkout).
//! Does not talk to the network.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use loom::insights::{analyze_trees, read_tree, seal_standalone};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Parser)]
#[command(
    name = "loom-insights",
    version,
    about = "Pre-flight insights on two materialized trees"
)]
struct Cli {
    /// Absolute base tree (protected-ref materialization).
    #[arg(long)]
    base: PathBuf,
    /// Absolute head tree (candidate materialization).
    #[arg(long)]
    head: PathBuf,
    /// Repository namespace used in the bundle.
    #[arg(long, default_value = "repo")]
    repository: String,
}

fn main() -> ExitCode {
    if let Err(error) = run(&Cli::parse()) {
        eprintln!("loom-insights: {error}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let base_files = read_tree(&cli.base)?;
    let head_files = read_tree(&cli.head)?;
    let base_rev = tree_digest(&base_files);
    let head_rev = tree_digest(&head_files);
    let (repo, _base_graph, _head_graph) = analyze_trees(
        &cli.repository,
        &base_rev,
        &head_rev,
        &base_files,
        &head_files,
    );
    let source_key = format!("{}:{}:{}", cli.repository, base_rev, head_rev);
    let bundle = seal_standalone(source_key, vec![repo]);
    serde_json::to_writer(std::io::stdout(), &bundle)?;
    println!();
    Ok(())
}

fn tree_digest(files: &std::collections::BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for (path, contents) in files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(contents);
    }
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(ALPHABET[usize::from(byte >> 4)]),
                char::from(ALPHABET[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}
