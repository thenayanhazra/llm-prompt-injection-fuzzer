# Contributing

## Adding payloads

The fastest way to contribute is adding new injection test cases. You have two options:

**Option A: Python corpus module.** Add payloads to `injection_fuzzer/payloads/corpus.py` or `advanced.py`. Each payload needs a unique ID, a canary string, and at least one message. Follow the existing pattern.

**Option B: YAML file.** Create a standalone YAML file (see `examples/custom-payloads.yaml` for the format) and submit it to the `examples/` directory. Users can load it with `--custom-payloads`.

Guidelines for good payloads:

- Test one technique per payload. Don't combine encoding + persona in a single test — that makes it hard to diagnose what bypassed.
- Use descriptive IDs: `indirect-csv-injection`, not `test-042`.
- Set severity based on real-world impact: a model parroting a harmless canary is `low`; a model following instructions to exfiltrate data from tool results is `critical`.
- Write a clear `description` field. Someone reading the report should understand what the payload tests without reading the message content.

## Adding providers

Subclass `injection_fuzzer.providers.base.Provider`, implement `send()` and `close()`, then register it in `providers/factory.py`.

## Running tests

```bash
make dev
make test
make lint
```

## Code style

- Ruff for linting (config in `pyproject.toml`)
- Type annotations on all public functions
- No dependencies beyond what's in `pyproject.toml` without discussion
