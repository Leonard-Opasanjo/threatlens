# Contributing

Bug reports, new sources, better heuristics and format importers are welcome.

## Set up

```bash
git clone https://github.com/Leonard-Opasanjo/threatlens.git
cd threatlens
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

```bash
ruff check .
pytest
bandit -q -c pyproject.toml -r threatlens
pip-audit
```

The tests must stay offline. A source that talks to the network takes an injectable function (see `load_feeds`
and `Dns`) so the tests can replace it.

## Adding a source

Write a class with a `name` attribute and a `signals(self, indicator) -> list[Signal]` method in
`threatlens/enrich.py`, and add it to the source list in `web.enricher` and `cli._enricher`. A signal's `verdict`
is `malicious`, `suspicious`, `benign` or `info`, and its `weight` feeds `score()`; keep weights consistent with
the table in the README (3 for a list match, 1 or 2 for a heuristic, 0 for information). A source must never
request the indicator itself; lookups against a database or a reputation API are fine, fetching the URL is not.

## Adding a heuristic

Heuristics live in `Structural`. Each one is a signal with a plain-language note. Add a positive and a negative
case to `tests/test_enrich.py`; false positives on common legitimate names are the thing to watch for, so test
against a few of those too.

## Adding a feed

Local feed files go in `threatlens/feeds/` with an entry in `feeds.json`. Bundled malicious feeds must stay
synthetic (reserved names and documentation address ranges). Public feeds are added as `url` entries; only sources
with clear terms allowing automated download belong there.

## Adding an import format

Importers in `threatlens/ioc.py` turn text into a list of `Indicator` through `classify`. Keep that path: the
store must never see an unclassified value.

## Security issues

See [SECURITY.md](SECURITY.md).
