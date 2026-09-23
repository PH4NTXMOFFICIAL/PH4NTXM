# [ CONTRIBUTING ]

PH4NTXM is an experimental system-level project focused on identity adaption, runtime consistency, and stateless execution.  
Contributions are welcome but must respect the core principles of the system.

## [ BEFORE YOU CONTRIBUTE ]

Keep the session identity chain consistent across hardware, browser and network components. Preserve stateless execution and the active mode's behavior.

## [ WAYS TO CONTRIBUTE ]

You can help by auditing system behavior, testing edge cases, improving documentation, proposing architectural improvements, or submitting patches.

## [ REPORTING ISSUES ]

Include the source commit or release tag, edition, boot mode, reproduction steps, and expected versus observed behavior. Distinguish bare-metal tests from VM tests.

## [ SUBMITTING CHANGES ]

Fork the repository, create a focused branch, and submit a pull request explaining the change and its checks. Report which checks passed, failed, or were not run.  
Each commit should contain one complete change, including its related code, build integration, required tests and documentation. Keep unrelated work in separate commits.

## [ COMMIT MESSAGES ]

Use `type(scope): description`, naming the affected component and the resulting behavior. Use `feat` for new functionality and `fix` for bug fixes. Other focused changes use `docs`, `test`, `build`, or `refactor`. Refactoring preserves behavior.  
Related documentation and tests can belong in the feature or fix commit. Sign commits with `git commit -S` and use the current date.

## [ CODE & DESIGN EXPECTATIONS ]

Match the surrounding layout and indentation, and preserve the PH4NTXM/GPL banners. Keep explanations in the component documentation rather than inline comments or docstrings.

For session docs, keep the shared OVERVIEW, STARTUP, RUNTIME, CHECKS and SOURCE layout. Describe the actual inputs, output and failure behavior. Compare related normal-mode and Lone Wolf pages, and keep examples tied to commands the current scripts support.  
Avoid unnecessary complexity, persistence mechanisms, identity-generation bypasses, and changes outside the session model.

## [ REVIEW PROCESS ]

All contributions are reviewed manually.  
Acceptance depends on alignment with project philosophy, validation results, and consistency with the existing architecture.

## [ SECURITY CONSIDERATIONS ]

Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
