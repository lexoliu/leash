//! Debug sandbox to identify the issue

use leash::{AllowAll, Sandbox, SandboxConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Creating sandbox...");
    let config = SandboxConfig::builder().network(AllowAll).build()?;
    let sandbox = smol::block_on(Sandbox::with_config(config))?;
    println!("Sandbox created at: {:?}", sandbox.working_dir());

    println!("\nRunning simple 'echo' command (stdout/stderr inherited)...");
    let status = match smol::block_on(sandbox.command("echo").args(["hello"]).status()) {
        Ok(status) => status,
        Err(e) => {
            // Check for environmental errors that we can't fix in CI
            match &e {
                leash::Error::UnsupportedPlatformVersion { .. }
                | leash::Error::NotEnforced(_)
                | leash::Error::InitFailed(_) => {
                    eprintln!("Skipping test due to environment limitations: {}", e);
                    return Ok(());
                }
                _ => {}
            }

            eprintln!("Failed with error: {:#?}", e);
            if let Some(source) = std::error::Error::source(&e) {
                eprintln!("Caused by: {:#?}", source);
            }
            return Err(e.into());
        }
    };

    println!("Success!");
    println!("Exit code: {:?}", status.code());

    Ok(())
}
