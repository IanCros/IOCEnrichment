# IOC-X Architecture

## Overview

IOC-X follows a layered architecture with clear separation of concerns.

## Layers

### IOCX.Domain

The core of the application. Contains domain models, enums, interfaces, and core concepts.

**Dependencies**: None (pure domain logic)

**Must NOT depend on**:
- WPF
- Entity Framework Core
- HTTP clients
- External API SDKs
- Infrastructure implementations

### IOCX.Application

Application services and orchestration. Contains business logic, classification, normalization, analysis, scoring, and enrichment orchestration.

**Dependencies**: IOCX.Domain only

### IOCX.Infrastructure

External integrations and persistence. Contains EF Core/SQLite, repositories, HTTP client, and provider implementations.

**Dependencies**: IOCX.Application, EF Core, SQLite

### IOCX.Wpf

Desktop presentation layer. Contains Views, ViewModels, and application bootstrap.

**Dependencies**: IOCX.Application, IOCX.Infrastructure, WPF

## Design Principles

### Dependency Inversion

All external dependencies are abstracted behind interfaces in the Domain or Application layers.

### Immutability

Domain models use immutable patterns with init-only properties and sealed classes.

### Null Safety

Nullable reference types are enabled across all projects.

### Async-First

All I/O operations are asynchronous with CancellationToken support.

## Data Flow

### Investigation Workflow

```
User Input (IOC string)
    ↓
IIocFactory.TryCreate()
    ↓
Ioc (classified, normalized)
    ↓
IEnrichmentService.EnrichAsync()
    ↓
ProviderResult[] (concurrent, rate-limited)
    ↓
IInvestigationAnalysisService.AnalyzeAsync()
    ↓
InvestigationResult (risk, confidence, evidence, relationships)
    ↓
Persistence (InvestigationRepository)
    ↓
UI Display
```

## Security

- No credentials in source code
- API keys via environment variables or configuration
- All external data treated as untrusted
- HTML-escaped output in reports
- Passive enrichment only
- No command execution based on IOC data