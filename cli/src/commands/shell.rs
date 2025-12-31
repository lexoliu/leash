use crate::cli::ShellArgs;
use crate::config::MergedConfig;
use crate::error::CliResult;
use crate::sandbox::create_sandbox;

pub async fn execute(args: ShellArgs, config: MergedConfig) -> CliResult<()> {
    let exit_code = {
        let mut sandbox = create_sandbox(&config).await?;

        if config.keep_working_dir {
            sandbox.keep_working_dir();
        }

        // Use bash by default for predictable sandbox behavior
        let shell = args
            .shell
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/bin/bash".to_string());

        // Build environment variables from config
        let envs: Vec<(String, String)> = config
            .env_set
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Run the shell with PTY support for proper terminal handling
        let status = sandbox.run_interactive(&shell, &[], &envs)?;
        status.code()
        // sandbox dropped here, working dir cleaned up
    };

    std::process::exit(exit_code);
}
