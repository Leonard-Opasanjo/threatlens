# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Leonard-Opasanjo/threatlens/security/advisories/new>.
Describe the input that triggers the problem and the mode (offline or online). You should hear back within seven
days.

## In scope

- Any way to make ThreatLens send a request to an indicator (fetch a URL, connect to an address) in any mode.
- Any way for imported data to execute code, read or write files outside the database, or alter other records.
- A value shown on a dashboard page, printed by the CLI or written to the Markdown report without defanging. The
  JSON export and the API return canonical values on purpose.
- A way for another web page to change data in, or read data from, a dashboard running on localhost.
- Cross-site scripting or injection in the dashboard or the report through indicator values, tags or notes.
- Online feed handling that would accept content from somewhere other than the configured URL, or that would
  run anything in the downloaded content.

## Out of scope

- Verdicts that are wrong because a list is incomplete or a heuristic misfires. Those are improvements.
- The dashboard having no authentication; it binds to localhost by design.
- Behaviour of the public feeds' content.

## Design notes

`threatlens/ioc.py` is the only place input becomes an indicator; `threatlens/enrich.py` is the only place the
network can be reached, and only through `load_feeds(online=True)` and `Dns`. Reviewers should check those two
files first.
