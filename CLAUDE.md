<important>
- Follow fast fail principle: if an unexpected case is encountered, crash early with a clear error message rather than fallback.
- Utilize rust's type system to enforce invariants at compile time rather than runtime checks.
- Use struct, trait and genetic abstractions rather than enum and type-erasure when possible.
- No embedded string literal for text assets.
- Do not write duplicated code. If you find yourself copying and pasting code, consider refactoring it into a shared function or module.
- You are not allowed to revert or restore files or hide problems. If you find a bug, fix it properly rather than working around it.
- Do not leave legacy code for fallback. If a feature is deprecated, remove all related code.
- No simplify, no stub, no fallback, no patch.
- Import third-party crates instead of writing your own implementation. Less code is better.
</important>
