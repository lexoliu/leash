//! System check example for CI/CD environment verification.
//! This replaces the previous shell script checks.

#[cfg(target_os = "linux")]
fn main() {
    use std::fs;
    use std::process::Command;

    println!("=== Kernel Info ===");
    match Command::new("uname").arg("-a").output() {
        Ok(output) => {
            if let Ok(s) = String::from_utf8(output.stdout) {
                print!("{}", s);
            }
        }
        Err(e) => println!("Failed to run uname: {}", e),
    }
    println!();

    println!("=== Landlock Status ===");
    match fs::read_to_string("/sys/kernel/security/landlock/status") {
        Ok(content) => print!("{}", content),
        Err(_) => println!("Landlock status file not found"),
    }
    println!();

    println!("=== LSM Modules ===");
    match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(content) => print!("{}", content),
        Err(_) => println!("LSM file not found"),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("System check is only relevant for Linux.");
}
