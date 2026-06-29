# Contributing to CyberSiren

Thanks for your interest in CyberSiren. This document explains how to contribute
code, report problems, and get help. These guidelines also satisfy the community
requirements for our Journal of Open Source Software (JOSS) submission.

## Reporting issues or problems

Please open an issue at <https://github.com/XHCFS/cybersiren/issues>. When reporting
a bug, include:

- what you ran (the `make` target or command),
- what you expected and what happened,
- relevant logs or trace output (services emit structured logs and OpenTelemetry traces),
- your OS, Go version, Python version, and Docker/Compose versions.

For security-sensitive reports, please open a minimal issue asking the maintainers to
contact you rather than posting exploit details publicly.

## Seeking support

- Read the README and the published documentation at <https://xhcfs.github.io/cybersiren/>.
- For usage questions, open a GitHub issue with the `question` label.

## Contributing code

1. **Discuss first.** For non-trivial changes, open an issue describing the change before
   sending a pull request.
2. **Fork and branch.** Create a topic branch from `main`.
3. **Develop and test locally:**
   ```bash
   make up                # start infra (postgres, valkey, kafka, jaeger)
   make test-short        # unit tests, no infra required
   make test-svc svc=svc-03-url-analysis
   make lint
   make build
   ```
   Python services have their own tests under each service's `nlp/` or `ml/` directory.
4. **Keep tests green and add tests** for new behaviour. CI runs the Go and Python test
   suites and linting on every pull request (`.github/workflows/ci.yml`).
5. **Match the surrounding style.** Go code is formatted with `gofmt`/`golangci-lint`;
   Python follows the existing module conventions.
6. **Open a pull request** against `main` with a clear description and a link to the issue
   it addresses. A maintainer will review it.

## Code of conduct

Be respectful and constructive. Harassment or abusive behaviour is not tolerated.
Maintainers may remove comments, commits, or contributions that violate this principle.

## License

By contributing, you agree that your contributions will be licensed under the project's
MIT License (see `LICENSE`).
