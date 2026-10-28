# Web Recon Toolkit

A Python web reconnaissance tool that collects basic HTTP metadata and reports on common security-related response headers.

## Features

- HTTP and HTTPS URL normalization and validation
- DNS resolution and rejection of non-public IP addresses
- Direct connections to validated IP addresses to reduce DNS rebinding risk
- Original hostname preservation for HTTP Host headers and HTTPS certificate verification
- HTTP status, content type, server, redirect location, and bounded response sampling
- Checks for common security response headers
- JSON and Markdown report generation
- Automated unit tests

## Security Headers Checked

- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

A missing header is an observation, not proof of a vulnerability. Requirements depend on the application and deployment.

## Requirements

- Python 3
- Python standard library

## Usage

Run the tool:

    python recon.py

Run tests:

    python -m unittest discover -s tests -v

Reports are written to the `output/` directory.

## Implementation Notes

The HTTP client connects to a previously validated IP address instead of resolving the hostname again when opening the TCP connection. For HTTPS, the original hostname is retained for TLS certificate verification.

Redirects are not automatically followed. The redirect response and its Location header are recorded for inspection.

## Responsible Use

Use this tool only on systems you own or have explicit authorization to assess. Public IP validation is a safety measure, not permission to test a target.

## Project Status

This is an educational portfolio project. Network behavior in the automated tests is mocked; integration testing against an authorized environment is still needed.
