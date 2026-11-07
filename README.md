# Lauda Recon

Lauda Recon is a Python 3.11+ orchestration wrapper for **authorized** bug-bounty and penetration-testing reconnaissance. Rather than reimplementing scanners, it coordinates optional best-of-breed binaries: Subfinder, Amass, PureDNS, HTTPX, Katana, GAU, and TruffleHog.

It favors evidence over noisy claims. A `verified` result means the specific DNS/HTTP/structural check documented in the report succeeded; it never means “guaranteed exploitable.” No recon tool can promise 100% coverage or zero false positives.

## What it does

```text
approved scope
  ├─ concurrent passive sources: Subfinder + Amass + GAU
  ├─ normalization, deduplication, bounded in-scope DNS mutations
  ├─ resolver-backed validation + wildcard-DNS filtering
  ├─ HTTPX service discovery on configured ports
  ├─ Katana, GAU, robots.txt, sitemap.xml endpoint collection
  └─ technology-aware path checks + soft-404 + structural evidence gates
       └─ text / JSON evidence reports
```

Subfinder and Amass use their own documented provider configurations, so available sources can include CRT.sh, AlienVault/OTX, Censys, Chaos, Hackertarget, and others supported by the installed versions and your approved API access. The wrapper deliberately does not embed provider credentials.

## Safety and verification boundaries

- Every active stage requires `--authorized` and `--active`; passive-only collection is the default.
- All hostnames are normalized and scope-checked. Explicit exclusions override root-domain matches.
- Redirects are never followed, so a request cannot silently leave scope.
- Wildcard DNS needs matching answers for multiple random in-scope labels before filtering is applied.
- Directory candidates are selected from detected tech (`PHP`, `IIS`, `Django`, `Node`, etc.), then compared to two randomized soft-404 baselines.
- Sensitive-file leads require multiple structural markers in two separate HTTP responses. Raw response content and values are not stored in reports.
- Takeover results require both a provider CNAME pattern and a public provider error signature; they remain **manual-review candidates** and never claim a resource.

The tool intentionally does **not**:

- authenticate to AWS, GitHub, Slack, Stripe, Firebase, or any provider with a discovered secret;
- retain or print a discovered credential value; or
- rotate PATs to circumvent GitHub or other provider rate limits.

GitHub Code Search uses at most one token supplied by an environment-variable name, and returns repository/path references only. Optional `trufflehog git` history scans return opaque, redacted indicators only.

## Install

Install the Python package and then install the external binaries you are allowed to use in the engagement.

```powershell
python -m pip install -e .
Copy-Item .\config\example.yaml .\config\local.yaml
lauda-recon --help
```

For an uninstalled source checkout, use the included launcher:

```powershell
python .\lauda.py --help
```

## Usage

Check the local tool inventory without running anything:

```powershell
python .\lauda.py -d example.com --check-tools
```

Validate the scope/configuration and see the planned workflow without opening a socket or starting a subprocess:

```powershell
python .\lauda.py -d example.com --authorized --config .\config\local.yaml --dry-run
```

Run approved active collection and write both requested output formats:

```powershell
python .\lauda.py -d example.com --authorized --active `
  --config .\config\local.yaml `
  -o .\reports\example.com.txt `
  -oJ .\reports\example.com.json
```

The CLI flags requested for automation are supported:

- `-d`, `--domain` — approved root domain (required)
- `-o`, `--output` — human-readable text report
- `-oJ`, `--json` — structured JSON evidence report
- `--active` — enable bounded active DNS/HTTP/content verification
- `--scope-file` — extra approved hostname patterns, one per line
- `--workers` — process/request concurrency cap (1–32)

Use JSON output as an evidence feed for a downstream workflow. It is intentionally not a claim-compatible Nuclei template or a stream of raw scanner output.

## GitHub and history configuration

Set one authorized token only if you want public code-reference searching:

```powershell
$env:GITHUB_TOKEN = "your-authorized-token"
```

Do not put the token in YAML or reports. For an explicitly authorized repository history scan, add the repository reference under `github.repositories` in `config/local.yaml`, enable `trufflehog`, and handle any lead through your program’s secure disclosure process.

## Project layout

```text
.
├── lauda.py                    # source-checkout launcher
├── pyproject.toml              # package / console-script metadata
├── config/
│   └── example.yaml            # safe scope, rate, tool configuration
├── src/lauda_recon/
│   ├── cli.py                  # -d, -o, -oJ and status output
│   ├── config.py               # typed fail-closed YAML/JSON config
│   ├── orchestrator.py         # dependency-aware concurrent pipeline
│   ├── tools.py                # shell-free external binary adapters
│   ├── parsing.py              # normalized, redaction-first parsers
│   ├── scope.py                # hostname scope and wildcard controls
│   ├── mutations.py            # bounded in-scope DNS permutations
│   ├── verify.py               # HTTP, soft-404, structure, takeover checks
│   ├── endpoints.py            # robots/sitemap extraction
│   ├── content.py              # technology-aware candidate paths
│   ├── github.py               # single-token reference search
│   ├── models.py               # assets, evidence, finding contracts
│   └── reporting.py            # redacted terminal/text/JSON rendering
└── tests/                      # offline safety and report tests
```

## Notes on configuration

Start with [config/example.yaml](config/example.yaml). Configure upstream API keys in each tool’s own supported configuration file/environment; do not place secrets in Lauda’s config. Supply `resolvers_file` only when you have a trusted resolver list for PureDNS. Keep rate limits conservative and comply with the specific program’s rules of engagement.
