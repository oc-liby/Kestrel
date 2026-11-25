# Reporting And Evidence

Use this file to normalize final evidence and replay handoff after browser, Android, desktop-client, Web, or AI/MCP work.

## Minimum Output

- scope and client type
- chosen MCP chain
- static findings
- runtime proof
- recovered request recipe
- Burp-ready baseline request
- security finding and mitigation

## Client-Controlled Targets

For browser or Android request-generation tasks, always include:

- target request and target field
- request-chain summary
- proven writer or sink
- upstream dependency or explicit statement that none exists
- runtime values that must be preserved
- replay-safe fields versus mutation-safe fields

## Recommended Templates

### Browser JS

- workflow: `browser-js-signing-workflow.md`
- persistent record: `browser-request-chain-template.md`

### Android

- workflow: `../../pentest-flow/references/_shared/android/android-signing-and-crypto-workflow.md`
- persistent record: `../../pentest-flow/references/_shared/android/android-signature-reverse-template.md`

## Final Handoff Checklist

- one real request sample is preserved
- replay prerequisites are explicit
- blockers are separated from proven facts
- the next operator can reproduce the baseline request
