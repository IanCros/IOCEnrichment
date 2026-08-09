# IOC-X

A C#/.NET desktop cybersecurity application for IOC enrichment and threat intelligence.

## Current Status

Stage 4 â€” Core Threat Intelligence Providers

## Architecture

```
Domain
   â†‘
Application
   â†‘
Infrastructure
```

- **IOCX.Domain** â€” Domain models, enums, interfaces, and core concepts.
- **IOCX.Application** â€” Application services for classification, normalization, provider framework, and enrichment.
- **IOCX.Infrastructure** â€” Persistence (EF Core/SQLite), repositories, and caching.

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

- `VT_API_KEY` â€” VirusTotal
- `ABUSEIPDB_API_KEY` â€” AbuseIPDB
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
---

## Intelligence Analysis Engine

IOC-X includes a deterministic, testable analysis engine that transforms provider results into security intelligence.

### Components

- **Risk Scoring**: Calculates 0-100 risk scores with evidence aggregation
- **Confidence Scoring**: Calculates 0-100% confidence based on evidence quality and provider coverage
- **IOC Correlation**: Identifies relationships between IOCs (ResolvesTo, AssociatedWithMalware, etc.)
- **Investigation Summary**: Generates human-readable investigation summaries
- **Analysis Orchestration**: Combines all components into a unified pipeline

### Analysis Pipeline

```
Provider Results → Correlation → Evidence → Risk Score → Confidence Score → Summary
```

### Risk Levels

| Score | Level |
|-------|-------|
| 0-19 | Informational |
| 20-39 | Low |
| 40-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

### Key Features

- Deterministic scoring (same input → same output)
- Provider-agnostic (operates on normalized results)
- Evidence-based (every score contribution is explainable)
- Confidence-aware (distinguishes missing evidence from no evidence)
- Relationship deduplication
- No external API calls or HTTP dependencies

### Documentation

- `docs/scoring.md` — Risk and confidence scoring details
- `docs/correlation.md` — Relationship types and inference rules