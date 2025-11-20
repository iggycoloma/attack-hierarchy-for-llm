# MITRE ATT&CK Hierarchy for LLM

## Overview

Turns MITRE ATT&CK's STIX 2.1 data into Markdown that LLMs can actually understand. Because apparently nobody wants to feed ~48MB of nested JSON into their RAG system and hope for the best. Now you get clean hierarchies with tactics → techniques → sub-techniques that won't make your vector database sad.

## Requirements

```
Python 3.11+
```

Dependencies:
- `mitreattack-python>=5.3.0` - MITRE ATT&CK STIX 2.1 parsing library

## Installation

### Using Dev Container (Recommended)

If you're using VS Code with the Dev Container extension (and you should be):

1. Open the project in VS Code
2. Click "Reopen in Container" when prompted
3. That's it. Everything just works. No fighting with Python versions or dependency hell.

Dependencies auto-install via `uv sync --extra dev` when the container spins up.

### Manual Setup (If You Hate Convenience)

```bash
# Clone it
git clone https://github.com/iggycoloma/attack-hierarchy-for-llm.git
cd attack-hierarchy-for-llm

# Get uv if you don't have it (seriously, get uv)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install everything
uv sync --extra dev

# Activate venv like it's 2015
source .venv/bin/activate  # Linux/macOS
# OR
.venv\Scripts\activate     # Windows
```

## Usage

### Download the MITRE ATT&CK dataset

```bash
# Easy mode
make download-fixtures

# Manual mode (for those who don't trust Makefiles)
curl -o tests/fixtures/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

### Run the parser

```bash
# Recommended (works without activating venv)
uv run python main.py --input tests/fixtures/enterprise-attack.json

# Or activate venv first
python main.py --input tests/fixtures/enterprise-attack.json

# Default behavior (checks project root for enterprise-attack.json)
uv run python main.py
```

Spits out `output/attack-hierarchy.md` with the full hierarchy.

### Command-line options

```bash
# Custom paths
python main.py --input tests/fixtures/enterprise-attack.json --output /path/to/output.md

# Verbose mode (when things go wrong)
python main.py --verbose

# Help (when all else fails)
python main.py --help
```

## Testing

```bash
# Run everything
pytest

# Just unit tests
pytest tests/unit/

# Just integration tests
pytest tests/integration/

# Coverage reports happen automatically:
# - Terminal: Shows what you missed
# - HTML: htmlcov/index.html (pretty colors)
# - XML: coverage.xml (for CI robots)
```

Coverage reports generate automatically because nobody should have to remember extra flags. Check `pyproject.toml` if you're curious about the config.

## Project Structure

```
attack-hierarchy-for-llm/
├── src/
│   └── attack_hierarchy/          # Main package
│       ├── __init__.py            # Package exports
│       ├── models.py              # Domain models (Tactic, Technique, SubTechnique)
│       ├── stix_parser.py         # STIX 2.1 parsing logic
│       ├── markdown_generator.py  # Markdown output formatting
│       └── py.typed               # PEP 561 type marker
│
├── tests/                         # Test suite
│   ├── fixtures/                  # Test data files
│   │   ├── README.md              # Fixture documentation
│   │   ├── minimal-attack.json    # Small test fixture (committed)
│   │   └── enterprise-attack.json # Full dataset (downloaded, gitignored)
│   ├── unit/                      # Unit tests
│   │   ├── test_models.py
│   │   ├── test_core.py
│   │   └── test_markdown_generator.py
│   └── integration/               # Integration tests
│       └── test_workflows.py
│
├── main.py                        # Main entry point
├── output/                        # Generated output files
├── pyproject.toml                 # Project configuration
├── .github/workflows/ci.yml       # CI/CD pipeline
└── README.md                      # This file
```

## Design Philosophy & Trade-offs

**Separation of Concerns**: Three layers: Models (data), Parsing (STIX stuff), Generation (Markdown stuff). Makes it trivial to swap formats or test things in isolation without everything exploding.

**Correctness Over Performance**: I use the official `mitreattack-python` library because writing my own STIX parser would be dumb. The dataset is only 15MB and parses in under a second, so no pressing need to optimize here.

**Duplication Over References**: Yes, techniques get repeated under each tactic they belong to. File size goes up, LLM comprehension goes way up.

**Minimal Dependencies**: Just `mitreattack-python` for the heavy lifting. It's maintained by people who actually know STIX, and it stays in sync with MITRE's format changes.

**Graceful Error Handling**: Missing IDs? Orphaned techniques? The parser logs warnings and keeps going instead of rage-quitting. You get partial output even when the data is a mess.

**Kill Chain Order**: Tactics follow the actual ATT&CK kill chain sequence instead of alphabetical order. Because "Reconnaissance → Initial Access → Execution" tells a story, and "Command and Control → Credential Access → Defense Evasion" does not.

## Sample Output

```markdown
# MITRE ATT&CK Enterprise Framework

**Statistics:** 14 tactics, 216 techniques, 475 sub-techniques

## [TA0043] Reconnaissance

### [T1595] Active Scanning

#### [T1595.001] Scanning IP Blocks
#### [T1595.002] Vulnerability Scanning
...
```

## What I'd Add for Production

**Schema Validation**:
- Actually validate against the STIX 2.1 JSON schema instead of just hoping
- Catch malformed data before the parser gets confused
- Auto-detect STIX versions because who wants to specify that manually

**Observability & Metrics**:
- Track how long each stage takes (so you know what to blame)
- Data quality metrics (how many orphaned techniques? missing fields?)
- Token count estimates for your LLM's context window budget
- Prometheus/DataDog integration (for when you need graphs to justify your existence)

**RAG-Optimized Output Formats**:

Right now this spits out one giant 2.6MB file with 42,000+ lines. Great for reading, terrible for RAG because:
- Your LLM's context window taps out way before line 42,000
- Chunking a single file means you're slicing across semantic boundaries
- All that duplication bloats your vector database

For actual production RAG systems, you'd want multiple output modes:

1. **Per-Tactic Files** (14 files): One file per kill chain phase
   - Clean semantic boundaries (each file = one phase of the attack)
   - Reasonable file sizes (~100-600 lines)
   - Perfect for "show me everything about initial access" queries
   - Usage: `python main.py --format by-tactic`

2. **Per-Technique Files** (216 files): One file per technique
   - Maximum granularity
   - Zero duplication (each technique appears exactly once)
   - Great for "what is T1595" lookups
   - Usage: `python main.py --format by-technique`

3. **Hybrid Approach** (Recommended for Real Stuff): All of the above
   - Both tactic files AND technique files
   - JSON indexes for cross-referencing
   - YAML front matter on everything for metadata filtering
   - Handles any query pattern you throw at it
   - Usage: `python main.py --format hybrid`

4. **Chunked with Metadata**: Single file, explicit chunk markers
   - HTML-style chunk boundaries in the file
   - Metadata tags tell your RAG pipeline where to split
   - Preserves hierarchy without breaking semantic relationships
   - For when you want one file but don't want to think about chunking

All of these would include YAML front matter like:
```yaml
---
id: TA0043
type: tactic
name: Reconnaissance
technique_count: 10
kill_chain_phase: reconnaissance
---
```

Makes semantic search, metadata filtering, and hybrid retrieval actually work instead of just being buzzwords.

## Known Limitations

### Data Sources Not Included

Data sources aren't in the output. Not because I forgot, but because MITRE's STIX 2.1 format doesn't actually link them to techniques. The data is *in there* (109 data components, 38 data sources), but there are zero relationship objects connecting them. The `get_datacomponents_detecting_technique()` method returns empty arrays for everything?

**Workarounds if you really need this:**
1. Use the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (they somehow have the mappings)
2. Hit the [ATT&CK API](https://github.com/mitre-attack/attack-scripts) directly
3. Write a scraper for the [ATT&CK website](https://attack.mitre.org/) (I'm not judging)

**What you DO get:**
- Platforms (Windows, Linux, macOS, all the usual suspects)
- Detection info (when it exists)
- Mitigations (M-codes with actual names)
- Threat groups using each technique
- Software/malware implementing each technique
- External references (research papers, blog posts, the good stuff)

## License

MIT License - See LICENSE file for details.

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [ATT&CK STIX Data Repository](https://github.com/mitre-attack/attack-stix-data)

## Contributing

This started as a technical exercise but here we are. If you want to contribute:

1. PRs welcome, issues welcome
2. Write tests. Seriously. The linters will yell at you if you don't
3. Black, isort, and pylint run automatically—just let them do their thing
4. Update docs if you change something significant

## Acknowledgments

- MITRE Corporation for making ATT&CK and not charging money for it
- The OASIS CTI Technical Committee for STIX (even though it's a pain to parse)
