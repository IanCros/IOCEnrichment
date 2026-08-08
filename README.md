# IOC-X

A C#/.NET desktop cybersecurity application for IOC enrichment and threat intelligence.

## Current Status

Stage 4 — Core Threat Intelligence Providers

## Architecture

```
Domain
   ↑
Application
   ↑
Infrastructure
```

- **IOCX.Domain** — Domain models, enums, interfaces, and core concepts.
- **IOCX.Application** — Application services for classification, normalization, provider framework, and enrichment.
- **IOCX.Infrastructure** — Persistence (EF Core/SQLite), repositories, and caching.

## Supported IOC Types

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
- Email

## Threat Intelligence Providers

IOC-X currently integrates with three providers:

| Provider | Supported IOC Types |
|----------|-------------------|
| VirusTotal | IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 |
| AbuseIPDB | IPv4, IPv6 |
| ThreatFox | IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 |

See [docs/providers.md](docs/providers.md) for full provider documentation.

### Configuration

Provider API keys are read from environment variables:

- `VT_API_KEY` — VirusTotal
- `ABUSEIPDB_API_KEY` — AbuseIPDB
- ThreatFox does not require authentication for search queries

## Testing

Run the test suite:

```bash
dotnet test
```

## Build

Build the solution:

```bash
dotnet build