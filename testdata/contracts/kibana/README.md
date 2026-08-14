# Kibana contract fixtures

These fixtures are sanitized response projections derived from the pinned public Kibana OpenAPI schemas recorded in each version's `contract.json`.

- They contain synthetic IDs, users, timestamps, names, and messages.
- They contain no API keys or captured deployment data.
- They are intended for adapter request/response, pagination, error-classification, and redaction tests.
- They are not live captures and do not by themselves prove runtime compatibility.

When the public contract changes, update the operation manifest, fixtures, source URL/hash, `docs/kibana-api-contracts.md`, adapter tests, and live matrix together.
