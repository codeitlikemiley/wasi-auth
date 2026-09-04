//! Command-line entrypoint for PostgreSQL auth schema administration.

use std::process::ExitCode;

use wasi_auth_migrate::{MigrationCommand, backfill_organization_slugs, run};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match execute().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wasi-auth migration failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let Some(command) = arguments.next() else {
        return Err(usage().into());
    };
    if matches!(command.as_str(), "--help" | "-h") {
        println!("{}", usage());
        return Ok(());
    }
    let backfill = command == "backfill-organization-slugs";
    let command = if backfill {
        None
    } else {
        Some(parse_command(&command)?)
    };
    let mut database_url_environment = "DATABASE_URL".to_owned();
    let mut json = false;
    let mut batch_size = 500_u32;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--database-url-env" => {
                database_url_environment = arguments
                    .next()
                    .ok_or("--database-url-env requires a variable name")?;
            }
            "--json" => json = true,
            "--batch-size" if backfill => {
                batch_size = arguments
                    .next()
                    .ok_or("--batch-size requires an integer")?
                    .parse()
                    .map_err(|_| "--batch-size requires an integer")?;
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    let database_url = std::env::var(&database_url_environment).map_err(|_| {
        format!("required database URL environment variable {database_url_environment} is unset")
    })?;
    if backfill {
        let report = backfill_organization_slugs(&database_url, batch_size).await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("updated: {}", report.updated);
            println!("remaining: {}", report.remaining);
        }
        return Ok(());
    }
    let report = run(&database_url, command.ok_or("missing migration command")?).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("applied: {}", display_versions(&report.applied));
        println!("pending: {}", display_versions(&report.pending));
        println!("database verified: {}", report.database_verified);
    }
    Ok(())
}

fn parse_command(value: &str) -> Result<MigrationCommand, String> {
    match value {
        "plan" => Ok(MigrationCommand::Plan),
        "apply" => Ok(MigrationCommand::Apply),
        "verify" => Ok(MigrationCommand::Verify),
        "verify-database" => Ok(MigrationCommand::VerifyDatabase),
        "status" => Ok(MigrationCommand::Status),
        _ => Err(format!("unknown command {value}\n{}", usage())),
    }
}

fn display_versions(versions: &[String]) -> String {
    if versions.is_empty() {
        "none".to_owned()
    } else {
        versions.join(", ")
    }
}

fn usage() -> &'static str {
    "Usage: wasi-auth-migrate <plan|apply|verify|verify-database|status|backfill-organization-slugs> [--database-url-env NAME] [--batch-size 500] [--json]\n\nThe database URL is read from DATABASE_URL by default and is never accepted on the command line."
}
