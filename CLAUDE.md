# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**leash** (package name) / **native-sandbox** (repo name) is a cross-platform Rust library for running untrusted code in secure sandboxes with native OS-level isolation. Currently implements macOS via `sandbox-exec` with SBPL profiles; Linux (Landlock + Seccomp) and Windows (AppContainer) are declared but not yet implemented.

## Build Commands

```bash
cargo build                          # Debug build
cargo build --release                # Release build
cargo test                           # Run all tests
cargo run --example basic            # Run an example
cargo run --example python_sandbox   # Python venv example
```

## Architecture

### Core Components

- **Sandbox<N: NetworkPolicy>** (`src/sandbox.rs`) - Main entry point, generic over network policy. Manages lifecycle: creates backend, starts proxy, tracks child processes, cleans up on drop.

- **Command** (`src/command.rs`) - Builder for executing programs in sandbox. Automatically sets HTTP_PROXY/HTTPS_PROXY to route through sandbox proxy.

- **NetworkProxy** (`src/network/proxy.rs`) - Local HTTP proxy using hyper with executor-agnostic async. All sandboxed network traffic routes through this for policy enforcement.

- **NetworkPolicy** (`src/network/policy.rs`) - Trait for async network filtering. Implementations: `DenyAll` (default), `AllowAll`, `AllowList` (domain whitelist with wildcards), `CustomPolicy<F>`.

- **Backend trait** (`src/platform/mod.rs`) - Platform-specific sandbox execution. MacOS implementation uses `sandbox-exec` with SBPL profiles generated from Askama templates.

- **SecurityConfig** (`src/security.rs`) - Fine-grained protection toggles (protect_user_home, protect_credentials, protect_cloud_config, etc.) and hardware access flags (allow_gpu, allow_npu, allow_hardware).

### Key Patterns

- **Generic network policy**: `Sandbox<N: NetworkPolicy>` enables type-safe policy composition
- **Builder pattern**: All configuration via builders (SandboxConfigBuilder, SecurityConfigBuilder, etc.)
- **Compile-time templates**: SBPL profiles use Askama templates in `templates/`
- **Executor agnostic**: Works with any `executor-core` compatible runtime (smol default, tokio via feature)
- **Drop-based cleanup**: Sandbox drop kills child processes and removes working directory

### Module Structure

```
src/
├── lib.rs          # Public API re-exports
├── sandbox.rs      # Sandbox struct and lifecycle
├── command.rs      # Command builder
├── config.rs       # Configuration builders
├── security.rs     # SecurityConfig
├── workdir.rs      # Random-named working directories
├── platform/       # OS-specific backends
│   └── macos/      # sandbox-exec + SBPL
├── network/        # Proxy and policies
│   ├── policy.rs   # NetworkPolicy trait
│   └── proxy.rs    # HTTP proxy implementation
└── python/         # VenvManager for Python integration
```

## Code Standards

<important>
- Follow fast fail principle: if an unexpected case is encountered, crash early with a clear error message rather than fallback.
- Utilize rust's type system to enforce invariants at compile time rather than runtime checks.
- Use struct, trait and generic abstractions rather than enum and type-erasure when possible.
- No embedded string literal for text assets.
- Do not write duplicated code. If you find yourself copying and pasting code, consider refactoring it into a shared function or module.
- You are not allowed to revert or restore files or hide problems. If you find a bug, fix it properly rather than working around it.
- Do not leave legacy code for fallback. If a feature is deprecated, remove all related code.
- No simplify, no stub, no fallback, no patch.
- Import third-party crates instead of writing your own implementation. Less code is better.
- Async first and runtime agnostic.
- Be respectful to lints, do not disable lints without strong reason.
</important>
