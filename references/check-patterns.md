# MCP Audit — Check Patterns Reference

Grep patterns, severity classifications, and known package lists used by the mcp-security-audit skill.

## 1. Network and Data Exfiltration Patterns

### Outbound Network Calls

| Language | Pattern | Notes |
|----------|---------|-------|
| Node.js | `fetch\(` | Native fetch or node-fetch |
| Node.js | `axios` | Axios HTTP client |
| Node.js | `http\.get\(` `http\.request\(` `https\.get\(` `https\.request\(` | Core HTTP modules |
| Node.js | `net\.connect` `net\.createConnection` | Raw TCP |
| Node.js | `new WebSocket\(` `ws\(` | WebSocket connections |
| Node.js | `dns\.resolve` `dns\.lookup` | DNS resolution |
| Python | `requests\.(get\|post\|put\|delete\|patch\|head)` | Requests library |
| Python | `urllib\.request` `urllib\.urlopen` `urlopen\(` | Standard library HTTP |
| Python | `httpx\.(get\|post\|put\|delete\|patch\|AsyncClient)` | HTTPX async client |
| Python | `aiohttp\.(ClientSession\|request)` | Aiohttp client |
| Python | `socket\.connect` `socket\.create_connection` | Raw socket |
| Python | `dns\.resolver` | dnspython |
| Both | `WebSocket` `websocket` | WebSocket connections |

### Data Exfiltration Indicators

| Pattern | Severity | Condition |
|---------|----------|-----------|
| `btoa\(.*process\.env` | CRITICAL | Base64 encoding env vars |
| `Buffer\.from\(.*process\.env` | CRITICAL | Buffer encoding env vars |
| `base64\.b64encode.*os\.environ` | CRITICAL | Base64 encoding env vars |
| `base64\.b64encode.*os\.getenv` | CRITICAL | Base64 encoding env vars |
| Hardcoded external URL/IP (not localhost/127.0.0.1/::1) | HIGH | Unexpected outbound destination |
| Dynamic hostname construction (template literals/f-strings with variables) | HIGH | Destination determined at runtime |

---

## 2. Environment and Secrets Access Patterns

### Env Var Access

| Language | Pattern |
|----------|---------|
| Node.js | `process\.env\[` `process\.env\.` |
| Node.js | `dotenv` `require\('dotenv'\)` `config\(\)` |
| Python | `os\.environ` `os\.getenv\(` `os\.environ\.get\(` |
| Python | `load_dotenv` `dotenv_values` |
| Both | `\.env` file reads |

### Credential Env Var Prefixes

Flag access to these unless the server's stated purpose requires them:

```
AWS_ACCESS_KEY, AWS_SECRET, AWS_SESSION_TOKEN
GITHUB_TOKEN, GITHUB_PAT, GH_TOKEN
DATABASE_URL, DB_HOST, DB_PASSWORD, DB_USER
PRIVATE_KEY, SSH_KEY, SSL_CERT
OPENAI_API_KEY, ANTHROPIC_API_KEY, CLAUDE_API_KEY
STRIPE_SECRET, STRIPE_KEY
SENDGRID_API_KEY, MAILGUN_API_KEY
SLACK_TOKEN, SLACK_BOT_TOKEN, SLACK_WEBHOOK
GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_API_KEY
AZURE_CLIENT_SECRET, AZURE_TENANT_ID
REDIS_URL, REDIS_PASSWORD
MONGODB_URI, MONGO_PASSWORD
JWT_SECRET, SESSION_SECRET, ENCRYPTION_KEY
```

Any env var containing: `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `PRIVATE`, `API_KEY`

### Severity

| Finding | Severity |
|---------|----------|
| Accesses declared env var | NONE |
| Accesses undeclared env var (non-credential) | MEDIUM |
| Accesses undeclared credential env var | HIGH |
| Base64/hex encodes env var content | CRITICAL |

---

## 3. Code Integrity Patterns

### Dangerous Execution

These are grep patterns for detecting dangerous code constructs in audited codebases. They are detection signatures, not code to execute.

| Language | Detection Pattern | Default Severity |
|----------|-------------------|-----------------|
| Node.js | `eval\(` | HIGH |
| Node.js | `Function\(` (constructor pattern) | HIGH |
| Node.js | `child_process` `require\(.child_process.\)` `execSync\(` `exec\(` `spawn\(` | HIGH |
| Node.js | `vm\.runInNewContext` `vm\.createContext` | HIGH |
| Python | `eval\(` `exec\(` | HIGH |
| Python | `subprocess` `os\.system\(` `os\.popen\(` | HIGH |
| Python | `subprocess.*shell=True` | HIGH |
| Python | `__import__\(` `importlib\.import_module` | MEDIUM |
| Both | `eval` + user/network input within 10 lines | CRITICAL |

### Dynamic Code Loading

| Pattern | Severity |
|---------|----------|
| `import\(` with variable argument (not string literal) | MEDIUM |
| `require\(` with variable argument (not string literal) | MEDIUM |
| `fetch` + `eval` within same function | CRITICAL |
| `download` + `exec`/`spawn` within same function | CRITICAL |

### Obfuscation Indicators

| Indicator | Severity |
|-----------|----------|
| Source files with lines > 2000 characters | CRITICAL |
| `.min.js` files that are not in `node_modules/` | MEDIUM |
| Files with > 60% non-alphanumeric characters (excluding comments) | HIGH |
| Large base64 strings (> 500 chars) in source code | HIGH |
| Hex-encoded blocks (> 100 chars) in source code | HIGH |
| Binary files (.so, .dll, .wasm, .pyc) in source (not node_modules) | HIGH |

---

## 4. Persistence Mechanism Patterns

| Pattern | Severity |
|---------|----------|
| `crontab` `cron\.` | CRITICAL |
| `launchctl` `launchd` `LaunchAgent` `LaunchDaemon` | CRITICAL |
| `systemctl` `systemd` `\.service` file creation | CRITICAL |
| `\.bashrc` `\.zshrc` `\.profile` `\.bash_profile` (write context) | CRITICAL |
| `StartupItems` `LoginItems` | CRITICAL |
| `writeFile.*\/home\/` `writeFile.*\/Users\/` (absolute paths outside working dir) | HIGH |
| `open\(.*\/home\/` `open\(.*\/Users\/` with write mode | HIGH |
| `chmod` `chown` on system files | HIGH |

---

## 5. Permission Scope Patterns

### Filesystem Access

| Language | Pattern |
|----------|---------|
| Node.js | `fs\.readFile` `fs\.writeFile` `fs\.readdir` `fs\.mkdir` `fs\.unlink` `fs\.rmdir` |
| Node.js | `fs\.promises\.` `fsPromises\.` |
| Node.js | `path\.join\(.*__dirname` `path\.resolve\(` |
| Python | `open\(` `pathlib\.Path` `os\.path` `shutil\.` |
| Python | `os\.listdir` `os\.walk` `os\.makedirs` `os\.remove` `os\.rmdir` |

### Shell Execution

| Language | Pattern |
|----------|---------|
| Node.js | `child_process\.exec` `child_process\.spawn` `execSync` `spawnSync` |
| Python | `subprocess\.run` `subprocess\.Popen` `subprocess\.call` `os\.system` |

### Severity Rules for Scope

| Finding | Severity |
|---------|----------|
| Filesystem access matching stated tool purpose | NONE |
| Filesystem access beyond stated purpose | MEDIUM |
| Shell execution matching stated purpose (e.g. git tool) | LOW |
| Shell execution beyond stated purpose | HIGH |
| Unrestricted shell execution (user-supplied commands) | CRITICAL |

---

## 6. MCP-Specific Patterns

### Tool Registration

| Language | Pattern |
|----------|---------|
| Node.js (SDK) | `server\.tool\(` `server\.setRequestHandler\(ListToolsRequestSchema` |
| Node.js (SDK) | `name:.*description:` (tool definition objects) |
| Python (SDK) | `@server\.tool` `@mcp\.tool` |
| Python (SDK) | `Tool\(name=` `types\.Tool\(` |

### Transport Configuration

| Pattern | Expected | Flag If |
|---------|----------|---------|
| `StdioServerTransport` `stdio_server` | Default, safe | — |
| `SSEServerTransport` `sse` | Expands network surface | Flag as MEDIUM |
| `StreamableHTTPServerTransport` `http` | Expands network surface | Flag as MEDIUM |
| Listens on `0.0.0.0` | Accepts all interfaces | Flag as HIGH |

### Capability Requests

| Pattern | Severity |
|---------|----------|
| `capabilities.*roots` | MEDIUM — requests filesystem root access |
| `capabilities.*sampling` | MEDIUM — requests LLM sampling access |
| `capabilities.*logging` | LOW — standard |
| More than 15 registered tools | LOW — large attack surface |
| More than 30 registered tools | MEDIUM — very large attack surface |

---

## 7. Licence and Provenance

### Licence Files to Check

```
LICENSE, LICENSE.md, LICENSE.txt, LICENCE, LICENCE.md, LICENCE.txt, COPYING, COPYING.md
```

### Licence Classification

| Licence | Risk Level |
|---------|-----------|
| MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC | LOW (permissive) |
| MPL-2.0 | LOW (weak copyleft) |
| GPL-2.0, GPL-3.0, AGPL-3.0 | MEDIUM (copyleft — review implications) |
| SSPL, BSL, ELv2 | MEDIUM (restrictive) |
| No licence file | MEDIUM (all rights reserved by default) |
| Unknown/custom licence | MEDIUM (requires manual review) |

### Provenance Checks

| Check | Command | Flag If |
|-------|---------|---------|
| Commit count | `git log --oneline \| wc -l` | Under 5 commits |
| Author count | `git log --format='%an' \| sort -u \| wc -l` | Single author on popular-seeming project |
| Force-push indicators | `git reflog` (if available) | Rewritten history |
| Package name vs repo name | Compare `package.json` name / `pyproject.toml` name against directory name | Mismatch |
| Age of repo | `git log --reverse --format='%ai' \| head -1` | Created within last 30 days for a "popular" tool |

---

## 8. Known Legitimate MCP Packages

### Node.js

```
@modelcontextprotocol/sdk
@modelcontextprotocol/server-filesystem
@modelcontextprotocol/server-github
@modelcontextprotocol/server-postgres
@modelcontextprotocol/server-slack
@modelcontextprotocol/server-google-maps
@modelcontextprotocol/server-memory
@modelcontextprotocol/server-puppeteer
@modelcontextprotocol/server-brave-search
@modelcontextprotocol/server-fetch
@modelcontextprotocol/server-sequentialthinking
@modelcontextprotocol/server-everything
@modelcontextprotocol/inspector
```

### Python

```
mcp
fastmcp
mcp-server-fetch
mcp-server-git
mcp-server-sqlite
mcp-server-filesystem
mcp-server-time
mcp-server-sse
anthropic-mcp
```

Compare dependency names against these lists. Flag any dependency that is within Levenshtein distance 2 of a known package but not an exact match (potential typosquatting).
