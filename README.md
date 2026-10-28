# Web Recon Toolkit

[![Python Tests](https://github.com/RyanNupp1/web-recon/actions/workflows/tests.yml/badge.svg)](https://github.com/RyanNupp1/web-recon/actions/workflows/tests.yml)

A Python web reconnaissance tool for collecting basic HTTP response metadata and observing common security-related response headers. Built as a hands-on cybersecurity portfolio project.

## Features

- Normalizes and validates HTTP and HTTPS URLs.
- Resolves DNS and rejects targets resolving to non-public IP addresses.
- Connects to a validated IP address to reduce DNS rebinding risk.
- Preserves the original hostname for the HTTP Host header and HTTPS certificate verification.
- Records HTTP status, content type, server header, redirect location, and response bytes sampled.
- Observes six common security response headers.
- Generates JSON and Markdown reports.
- Includes automated unit tests and a GitHub Actions workflow.

## Example Report

The repository includes a demonstration report generated against `https://example.com`.

- [Read the sample Markdown report](examples/sample-report.md)
- [Inspect the sample JSON report](examples/sample-report.json)

The sample is an observation from one run, not a guarantee of the target's current configuration or security posture.

## Security Headers Observed

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

A missing header is not, by itself, proof of a vulnerability. Requirements depend on the application, its architecture, and its deployment.

## Requirements

- Python 3.13 or newer is recommended.
- Uses Python standard-library modules; no third-party packages are required.

## Usage

Clone the repository and enter the project directory:

    git clone https://github.com/RyanNupp1/web-recon.git
    cd web-recon

Run the tool:

    python recon.py

When prompted, enter an HTTP or HTTPS target you own or are authorized to assess. For the demonstration domain, use:

    https://example.com

The tool writes reports to `output/recon-report.json` and `output/recon-report.md`. These generated files are ignored by Git to avoid committing run-specific output.

Run the automated tests:

    python -m unittest discover -s tests -v

## Implementation Notes

The HTTP client connects to a previously validated IP address rather than resolving the hostname again for the TCP connection. For HTTPS, it retains the original hostname for TLS certificate verification.

Redirects are not automatically followed. Redirect responses and their `Location` headers are recorded for inspection. Response sampling is bounded to limit the amount of data read.

## Testing and Continuous Integration

The test suite uses mocked network behavior for deterministic unit tests. GitHub Actions runs the unit tests on pushes to `main` and on pull requests targeting `main`.

Passing unit tests does not replace integration testing against an authorized environment.

## Responsible Use

Use this tool only on systems you own or have explicit authorization to assess. Public-IP validation is a technical safeguard, not permission to test a target. This tool provides basic reconnaissance observations; it is not a comprehensive vulnerability scanner.

## Project Status

Educational portfolio project. Future improvements may include additional test coverage, more robust error handling, and authorized integration tests.
