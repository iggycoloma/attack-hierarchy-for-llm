# Test Fixtures for MITRE ATT&CK Hierarchy Parser

This directory contains test data files (fixtures) used by the test suite.

## Large Fixtures (Download Required)

### enterprise-attack.json (~51MB)

The full MITRE ATT&CK Enterprise dataset in STIX 2.1 format. This file is **not committed to git** due to its size and must be downloaded separately.

**Download via Makefile:**
```bash
make download-fixtures
```

**Download manually:**
```bash
curl -o tests/fixtures/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

**Used by:**
- Integration tests (tests/integration/)
- Full workflow testing
- Comprehensive data validation

**Note:** If this file is missing, integration tests will be skipped automatically with a helpful message. Unit tests will continue to work using the smaller committed fixtures.

## Small Fixtures (Committed to Git)

### minimal-attack.json (~5KB)

A minimal valid STIX 2.1 bundle containing:
- 1 tactic (TA0043 Reconnaissance)
- 1 technique (T1595 Active Scanning)
- 1 sub-technique (T1595.001 Scanning IP Blocks)
- 1 mitigation (M1056 Pre-compromise)
- Proper relationship mappings

**Used by:**
- Fast unit tests
- CI/CD pipelines (no download needed)
- Quick development iterations
- Testing core parsing logic

## Updating Fixtures

### Update to Latest MITRE ATT&CK Data

To get the latest version:
```bash
make download-fixtures
```

Check for new releases: https://github.com/mitre-attack/attack-stix-data/releases

### Create New Test Fixtures

To create additional test fixtures:

1. Start with minimal-attack.json as a template
2. Follow STIX 2.1 bundle format
3. Keep fixtures small (<1MB) if committing to git
4. Include representative examples of edge cases
5. Document in this README

## File Management

- **Committed:** minimal-attack.json (and any other small fixtures)
- **Gitignored:** enterprise-attack.json (must be downloaded)
- **CI/CD:** Automatically downloads enterprise-attack.json for integration tests

## Troubleshooting

**Missing enterprise-attack.json:** Run `make download-fixtures` or download manually with the curl command above.

**Tests being skipped:** Integration tests auto-skip when enterprise-attack.json is missing (expected behavior). Unit tests continue to run with minimal-attack.json.

**Download fails:** Verify internet connection and GitHub access, then retry with `make download-fixtures`.

## Additional Resources

- MITRE ATT&CK STIX Data: https://github.com/mitre-attack/attack-stix-data
- STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/
- Project Documentation: ../../README.md
