# IOC-X

IOC Enrichment & Threat Intelligence Platform

## Overview

IOC-X is a C#/.NET WPF desktop application for indicator of compromise (IOC) enrichment and threat intelligence analysis. It provides a unified workflow for classifying, normalizing, enriching, and analyzing IOCs using multiple threat intelligence providers.

## Features

- **IOC Classification**: Automatically identifies IPv4, IPv6, domains, URLs, MD5, SHA-1, SHA-256, and email addresses
- **Multi-Provider Enrichment**: Query VirusTotal, AbuseIPDB, ThreatFox, Shodan, URLhaus, DNS, and RDAP
- **Risk Scoring**: Deterministic 0-100 risk assessment with evidence aggregation
- **Confidence Scoring**: 0-100% confidence based on evidence quality and provider coverage
- **IOC Correlation**: Identifies relationships between IOCs (ResolvesTo, AssociatedWithMalware, etc.)
- **Investigation History**: Persistent storage of investigations with SQLite
- **Caching**: Intelligent caching to minimize redundant provider requests
- **Rate Limiting**: Respects provider rate limits with configurable concurrency
- **Export**: JSON, CSV, and HTML report generation
- **WPF Interface**: Modern dark-themed desktop UI with MVVM architecture

## Architecture

```
IOCX.Wpf
   -> IOCX.Application
     -> IOCX.Domain

IOCX.Infrastructure
   -> SQLite / EF Core
   -> HTTP / Providers
```

- **IOCX.Domain**: Domain models, enums, interfaces, and core concepts
- **IOCX.Application**: Application services for classification, normalization, analysis, scoring, and enrichment orchestration
- **IOCX.Infrastructure**: Persistence (EF Core/SQLite), repositories, HTTP client, and provider implementations
- **IOCX.Wpf**: WPF desktop application with MVVM pattern

## Supported IOC Types

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
- Email

## Installation

Requires the .NET 8 SDK. Building or running the desktop application requires Windows;
the Domain, Application, and Infrastructure projects and all tests are platform-neutral.

```bash
git clone <repository-url>
cd IOCEnrichment
dotnet restore IOCX.sln
dotnet build IOCX.sln
dotnet test IOCX.sln
dotnet run --project src/IOCX.Wpf
```

**IOC-X runs with no credentials**, using DNS and RDAP, which need no authentication. Providers
that require a key are skipped and reported as "Not configured" on the Settings and Dashboard
screens rather than failing the investigation.

For meaningful threat intelligence you want at least an abuse.ch key, which is free and covers
both ThreatFox and URLhaus. See [API keys](#api-keys) below.

## Configuration

Configuration is layered, lowest precedence first:

1. `appsettings.json` beside the executable — see `appsettings.example.json` for every option
2. `%APPDATA%\IOC-X\appsettings.json` — written by the in-app Settings screen
3. environment variables prefixed `IOCX_`, for example `IOCX_Network__TimeoutSeconds=30`

Configurable: which providers are enabled, per-provider rate limits, cache lifetime, request
timeout, concurrency, and every risk-scoring weight and threshold.

### API keys

Keys are never stored in configuration files. They are read through `ISecretStore`, which checks
environment variables first and then a DPAPI-encrypted store under `%APPDATA%\IOC-X\secrets.dat`.
Environment variables take precedence, so an operator can override a stored key without opening
the application.

| Provider | Variable | Free tier | Where to get one |
| --- | --- | --- | --- |
| ThreatFox | `ABUSECH_AUTH_KEY` | yes | [auth.abuse.ch](https://auth.abuse.ch/) |
| URLhaus | `ABUSECH_AUTH_KEY` | yes | same key as ThreatFox |
| VirusTotal | `VT_API_KEY` | yes | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | yes | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| Shodan | `SHODAN_API_KEY` | limited | [shodan.io](https://account.shodan.io/) |
| DNS, RDAP | — | n/a | no credentials needed |

abuse.ch made authentication mandatory for its community APIs; a single free Auth-Key covers
both ThreatFox and URLhaus, which is why they share one variable.

Either set the variables before launching, or enter keys on the Settings screen, where they are
encrypted for your Windows account. Keys are never logged and never displayed after entry.

## Usage

1. Launch the application and open **Settings** to confirm which providers are active.
2. Go to **Investigate** and enter an indicator, for example `192.0.2.1` or `example.com`.
3. Press **Analyze**. Long-running investigations can be cancelled; cancellation aborts the
   in-flight HTTP requests rather than merely detaching the UI from them.
4. Review the risk band, confidence, executive summary, per-signal evidence, per-provider
   results, and discovered relationships.
5. Every investigation is stored locally and appears under **History** and on the **Dashboard**,
   so repeat analysis of the same indicator builds a record of how its rating changed over time.

`examples/sample-iocs.txt` contains safe indicators drawn from reserved documentation ranges.

## Risk Scoring

Every investigation produces two independent numbers, because they answer different questions:

- **Risk (0–100)** — how adverse the findings are.
- **Confidence (0–100)** — how well corroborated those findings are.

HIGH risk at 30% confidence means one source saw something serious and nothing corroborated it.
HIGH risk at 95% confidence means several independent sources agree. Those warrant different
responses, which is why IOC-X refuses to collapse them into one number.

Scoring reads structured provider findings, never provider names or display text, so adding a
provider changes the score only through the facts it reports. Each signal emits an evidence item,
and the contributions of all evidence items sum exactly to the risk score — there is no hidden
term. Weights and band thresholds are configurable.

A score is an analytical aid, not a verdict. A score of 0 means the configured sources had
nothing to say, which is not the same as the indicator being clean. See
[docs/scoring.md](docs/scoring.md) for the full model and its limitations.

## Privacy

IOC-X is local-first. Indicators, investigation history, and cached responses stay on your
machine in a local SQLite database.

Analysing an indicator sends it to every enabled provider, which discloses it to that third
party and may be logged or retained by them. This is stated on the Settings screen, where each
provider can be disabled individually. Nothing is sent anywhere until you press Analyze.

## Security

IOC-X performs **passive enrichment only**:

- Never executes downloaded content
- Never opens malicious URLs automatically
- Never scans networks
- Never executes commands based on IOC data
- Treats all external data as untrusted
- Escapes all output in reports

## Testing

```bash
dotnet test IOCX.sln
```

The suite runs without API keys and without network access. Provider integrations are tested
against a mocked HTTP client covering 200, 401, 403, 429, 500, timeout, malformed JSON, and
missing fields. Fixtures use only reserved documentation ranges and domains, never real
infrastructure.

## Building

```bash
dotnet build IOCX.sln -c Release
```

To produce a self-contained Windows application that runs without a development environment:

```bash
dotnet publish src/IOCX.Wpf -c Release -r win-x64 --self-contained true -o ./publish
```

## Continuous Integration

GitHub Actions builds the solution, runs the full suite, verifies the Windows publish, and fails
the build if a credential-bearing file (`appsettings.json`, `.env`), a credential-shaped literal
under `src/`, or a `*.db` file is ever committed. CI requires no API keys.

## Documentation

- [docs/architecture.md](docs/architecture.md) — layering, data flow, and why each layer exists
- [docs/scoring.md](docs/scoring.md) — the risk and confidence models, and their limitations
- [docs/providers.md](docs/providers.md) — per-provider capabilities, fields, and failure behaviour
- [docs/correlation.md](docs/correlation.md) — relationship types and inference rules
- [docs/development.md](docs/development.md) — setup, adding a provider, conventions

## Roadmap

- Relationship graph visualization
- Bulk investigation from a file, with progress and summary statistics
- JSON, CSV, and HTML report export
- Additional threat intelligence providers
- STIX 2.1 mapping for the relationship model

## License

See LICENSE file.