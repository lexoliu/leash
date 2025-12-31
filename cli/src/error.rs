use std::process::ExitCode;

pub type CliResult<T> = anyhow::Result<T>;

/// Convert a CliResult to an ExitCode, printing errors to stderr
pub fn to_exit_code(result: CliResult<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            for cause in e.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            ExitCode::FAILURE
        }
    }
}
