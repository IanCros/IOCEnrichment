# IOC-X

A C#/.NET desktop cybersecurity application for IOC enrichment and threat intelligence.

## Current Status

Stage 1 — Foundation

## Architecture

```
Domain
   ↑
Application
```

- **IOCX.Domain** — Domain models, enums, interfaces, and core concepts.
- **IOCX.Application** — Application services for classification, normalization, and IOC creation.

## Supported IOC Types

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
- Email

## Testing

Run the test suite:

```bash
dotnet test
```

## Build

Build the solution:

```bash
dotnet build