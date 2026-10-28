# Threat model

## Assets
Source confidentiality, analysis integrity, API availability, and user trust in results.

## Threats
- False negatives or false positives from static heuristics
- Confidential source disclosure on remote deployments
- CPU/memory exhaustion from malicious input or external tools
- Toolchain vulnerabilities or unsafe compiler behavior
- Misinterpretation of a clean scan as a security guarantee

## Current mitigations
- 500,000-character source input cap
- No source persistence by the API
- Output escaped in browser rendering
- Tool timeouts for Slither and solc
- Clear disclaimer in UI and reports
- Docker runs as an unprivileged user and drops Linux capabilities

## Required before public hosting
- Authentication, per-user authorization, and rate limits
- Isolated worker/container per analysis, no network access by default
- CPU, memory, process-count, disk, and wall-clock limits
- Reverse proxy request/body limits
- Explicit source retention and privacy policy
- Dependency and image scanning
- Independent security review
