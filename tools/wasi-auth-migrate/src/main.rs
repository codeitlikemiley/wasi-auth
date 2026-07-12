//! Command-line entrypoint for the offline legacy authentication migration.

use std::path::PathBuf;
use std::process::ExitCode;

use wasi_auth_migrate::{MigrationConfig, load_key_file, migrate};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wasi-auth migration failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = None;
    let mut output = None;
    let mut key_file = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--input") => input = arguments.next().map(PathBuf::from),
            Some("--output") => output = arguments.next().map(PathBuf::from),
            Some("--key-file") => key_file = arguments.next().map(PathBuf::from),
            Some("--help" | "-h") => {
                println!(
                    "Usage: wasi-auth-migrate --input LEGACY_EVENTS.jsonl --output NEW_DIRECTORY --key-file AES256_KEY\n\nThe key file must contain 32 raw bytes or 64 hexadecimal characters. The output directory must not already exist."
                );
                return Ok(());
            }
            Some(other) => return Err(format!("unknown argument {other}").into()),
            None => return Err("arguments must be valid UTF-8".into()),
        }
    }

    let input = input.ok_or("--input is required")?;
    let output = output.ok_or("--output is required")?;
    let key_file = key_file.ok_or("--key-file is required")?;
    let key = load_key_file(&key_file)?;
    let report = migrate(&MigrationConfig { input, output, key })?;
    println!(
        "migrated {} events and {} secret records; verification passed",
        report.event_count, report.secret_count
    );
    Ok(())
}
