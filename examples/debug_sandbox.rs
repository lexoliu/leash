//! Debug sandbox to identify the issue

use leash::{DenyAll, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Creating sandbox...");
    let sandbox = smol::block_on(Sandbox::<DenyAll>::new())?;
    println!("Sandbox created at: {:?}", sandbox.working_dir());

    println!("\nRunning simple 'echo' command...");
    let output = smol::block_on(sandbox.command("echo").args(["hello"]).output());

    match output {
        Ok(out) => {
            println!("Success!");
            println!("Exit code: {:?}", out.status.code());
            println!("Stdout: {}", String::from_utf8_lossy(&out.stdout));
            println!("Stderr: {}", String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => {
            println!("Failed: {:?}", e);
        }
    }

    Ok(())
}
