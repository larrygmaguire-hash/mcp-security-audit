# MCP Security Audit

A Claude Code skill that performs structured security audits on third-party [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers before installation.

Point it at a GitHub URL or local directory and get a traffic-light risk rating with detailed findings across 8 security categories.

## What It Checks

| Category | What It Looks For |
|----------|-------------------|
| **Network & Data Exfiltration** | Outbound calls, hardcoded external domains, base64-encoded env vars |
| **Environment & Secrets** | Undeclared env var access, credential variable exposure |
| **Permission Scope** | Tools accessing resources beyond their stated purpose |
| **Code Integrity** | eval/exec, dynamic code loading, obfuscated source, encoded payloads |
| **Persistence Mechanisms** | Cron jobs, launch agents, dotfile writes, out-of-scope file writes |
| **Licence & Provenance** | Missing licence, low commit count, package name mismatches |
| **MCP-Specific** | Tool count, transport config, capability requests, broad resource URIs |
| **Tool Poisoning** | Tool descriptions that don't match implementation behaviour |

## Risk Ratings

| Rating | Indicator | Meaning |
|--------|-----------|---------|
| LOW | :green_circle: | Safe to install |
| MEDIUM | :yellow_circle: | Install with caution — review flagged items |
| HIGH | :orange_circle: | Do not install unless mitigations applied |
| CRITICAL | :red_circle: | Do not install |

## Installation

Copy the skill folder into your Claude Code project:

```bash
# From your project root
cp -r /path/to/mcp-security-audit .claude/skills/mcp-security-audit
```

Or clone directly:

```bash
git clone https://github.com/larrymaguire/mcp-security-audit.git
cp -r mcp-security-audit .claude/skills/mcp-security-audit
```

### Structure after install

```
your-project/
  .claude/
    skills/
      mcp-security-audit/
        SKILL.md
        references/
          check-patterns.md
```

## Prerequisites

- **git** — required for GitHub URL mode (clones the target repo)
- **npm** — required for Node.js dependency audit
- **pip-audit** — optional, for Python dependency audit (`pip install pip-audit`)

## Usage

### Audit from GitHub URL

```
/mcp-security-audit https://github.com/example/mcp-server-weather
```

### Audit from local directory

```
/mcp-security-audit /path/to/some-mcp-server
```

### What happens

1. **Source acquisition** — clones the repo (or reads from local path)
2. **Language detection** — identifies Node.js, Python, or hybrid
3. **Dependency analysis** — runs `npm audit` / `pip-audit`, checks for unpinned versions and typosquatting
4. **Static security scan** — 8 categories of grep-based pattern matching against the codebase
5. **Report compilation** — generates a markdown report with traffic-light rating
6. **Cleanup** — removes temp clone directory (if applicable)

### Output

A markdown report written to disk containing:

- Overall risk rating with summary
- Per-category findings table (severity, file:line, recommendation)
- Dependency report (total, transitive, unpinned, vulnerabilities)
- Environment variable analysis (declared vs actually accessed)
- Tool analysis (declared purpose vs actual capabilities)
- Actionable recommendation

## Example Output

```
## MCP Audit Complete: mcp-server-weather

**Risk Rating:** :yellow_circle: MEDIUM
**Findings:** 0 critical, 0 high, 2 medium, 1 low
**Recommendation:** INSTALL WITH CAUTION — review flagged items

Full report: ./2026-02-18-1430-mcp-audit-mcp-server-weather.md
```

## File Structure

```
mcp-security-audit/
  SKILL.md                       # Main skill instructions
  references/
    check-patterns.md            # Grep patterns, severity rules, known package lists
  README.md                      # This file
  LICENSE                        # MIT licence
```

## Customisation

### Adding known legitimate packages

Edit `references/check-patterns.md` section 8 to add packages to the allowlist. This prevents false typosquatting flags for packages you trust.

### Adjusting severity levels

Severity rules are defined in `references/check-patterns.md` under each category. Modify the severity column to match your risk tolerance.

### Changing report output location

Phase 6 of `SKILL.md` defines where reports are written. Edit the output directory path to suit your workspace.

## Limitations

- **Static analysis only** — does not execute the MCP server or observe runtime behaviour
- **Pattern-based** — may produce false positives for legitimate uses of flagged patterns (e.g. a git MCP server legitimately using `child_process`)
- **Dependency audit depth** — relies on `npm audit` / `pip-audit` databases, which may not cover all vulnerabilities
- **No network monitoring** — cannot detect data exfiltration that only occurs at runtime

## Contributing

Issues and pull requests welcome. When adding new check patterns:

1. Add the grep pattern to the appropriate section in `references/check-patterns.md`
2. Include the severity classification and any conditions
3. Update `SKILL.md` if the new pattern introduces a new category or changes the workflow

## Licence

MIT — see [LICENSE](LICENSE).
