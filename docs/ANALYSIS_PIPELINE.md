# Analysis pipeline

## Heuristics
The initial rules detect selected text patterns (`tx.origin`, low-level calls, floating compiler pragmas, missing SPDX header). They are intentionally explainable but not AST-aware.

## Slither
When `slither` is present and `use_slither` is enabled, BlockSentinel writes the submitted source to a temporary file, invokes Slither JSON output, and maps detector findings to the common schema. Slither may return a non-zero exit code when findings exist; the adapter attempts to parse stdout regardless.

## Solidity AST
When `solc` is present and `use_ast` is enabled, the adapter requests `ast` through Standard JSON. The current AST integration returns structural counts. It does not claim to detect vulnerabilities from the AST yet.

## SARIF
SARIF output uses version 2.1.0 and includes tool rules, locations, severity levels, messages, and stable fingerprints. The GitHub workflow uploads the SARIF artifact to code scanning.

## Baseline comparison
Findings compare by stable fingerprint. Line changes can produce a new fingerprint and therefore show as introduced/resolved; for long-lived projects, consider a semantic fingerprint strategy that excludes line numbers.
