# Development Guide

## Prerequisites

- .NET 8 SDK
- Windows, for building or running the desktop project (`IOCX.Wpf` targets `net8.0-windows`
  and uses WPF). The Domain, Application, and Infrastructure projects and all of their tests
  are platform-neutral.

## Getting started

```bash
git clone <repository-url>
cd IOCEnrichment
dotnet restore IOCX.sln
dotnet build IOCX.sln
dotnet test IOCX.sln
```

The test suite requires no API keys and makes no network requests. If a test ever needs the
internet to pass, that is a bug in the test.

## Running the application

```bash
dotnet run --project src/IOCX.Wpf
```

IOC-X runs with no credentials, using DNS and RDAP. Providers that need a key are skipped and
reported as "Not configured" on the Settings and Dashboard screens rather than failing.

For useful threat intelligence, get a free abuse.ch Auth-Key from https://auth.abuse.ch/ — one
key enables both ThreatFox and URLhaus.

### Verifying provider integrations by hand

Unit tests mock `IHttpClient`, which means they cannot catch a provider that authenticates
incorrectly: the mock returns 200 whatever headers you send. Historically every keyed provider
stored its key and never transmitted it, and the whole suite still passed.
`ProviderAuthenticationTests` now guards this by asserting on the outgoing request, but when you
add a provider, also run it once against the live API to confirm the credential is accepted.

## Project layout

| Project | Responsibility | May depend on |
| --- | --- | --- |
| `IOCX.Domain` | Models, enums, entities, and the interfaces at each boundary | nothing |
| `IOCX.Application` | Classification, normalization, providers, scoring, correlation, orchestration | Domain |
| `IOCX.Infrastructure` | EF Core persistence, secret storage, user settings | Application |
| `IOCX.Wpf` | Views, view models, dependency injection bootstrap | Application, Infrastructure |

The Domain project has no package references, which is the mechanism that keeps it independent.
If you find yourself wanting to add one, the type you are writing probably belongs a layer up.

## Adding a provider

The provider layer is designed so that this touches four files and nothing else — in particular,
it requires no change to the scoring engine or to any view.

1. **Implement `IEnrichmentProvider`** in `src/IOCX.Application/Providers/`. Translate the API
   response into `ProviderFindings`; do not let the provider's own JSON shape escape the class.
   Set `NormalizedData` to a readable summary for display, but never depend on parsing it back.

2. **Add a `ProviderDescriptor`** to
   [`ProviderCatalog.All`](../src/IOCX.Application/Providers/ProviderCatalog.cs), including the
   environment variable holding its key (or `null` when it needs none), the IOC types it
   supports, and a conservative rate-limit default.

3. **Add a case** to `ProviderRegistryFactory.Build`.

4. **Write tests** covering 200, 401, 403, 429, 500, timeout, malformed JSON, and missing
   fields, using the mocked HTTP client. Use only reserved documentation values in fixtures.

The Settings screen, Dashboard health list, and dependency injection all read from the catalog,
so the new provider appears in the UI without further work.

### Rate limits

The defaults in the catalog are chosen to sit well inside free-tier allowances, not to match
each service's published ceiling. Do not raise them from memory — check the provider's current
documentation, which is linked from its descriptor.

## Configuration and secrets

Configuration is layered, lowest precedence first:

1. `appsettings.json` beside the executable
2. `%APPDATA%\IOC-X\appsettings.json`, written by the Settings screen
3. environment variables prefixed `IOCX_` (for example `IOCX_Network__TimeoutSeconds=30`)

API keys never appear in any of these. They are read through
[`ISecretStore`](../src/IOCX.Domain/ISecretStore.cs), which checks environment variables first
and then a DPAPI-encrypted file under `%APPDATA%\IOC-X\secrets.dat`. Environment variables win,
so an operator can always override a stored key without opening the application.

For local development:

```bash
export VT_API_KEY=...           # or set VT_API_KEY=... on Windows
export ABUSEIPDB_API_KEY=...
export SHODAN_API_KEY=...
```

Never write a key into a tracked file. CI fails the build if `appsettings.json` or `.env`
becomes tracked, or if a credential-shaped literal appears under `src/`.

## Database

SQLite via EF Core, with migrations under `src/IOCX.Infrastructure/Migrations/`. The database
is created and migrated on startup.

```bash
dotnet tool restore
dotnet ef migrations add <Name> --project src/IOCX.Infrastructure --startup-project src/IOCX.Infrastructure
```

`*.db` files are gitignored. They contain the indicators you have investigated and cached
provider responses, so treat them as sensitive.

## Testing conventions

- **No network access.** Providers are tested against a mocked `IHttpClient`.
- **No real infrastructure in fixtures.** Use `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`, and `example.com` / `.net` / `.org`. See
  `examples/sample-iocs.txt`.
- **Test the contract, not the presentation.** Scoring tests build `ProviderFindings`
  directly. A test that asserts on the text of `NormalizedData` is testing the UI string.
- **Platform-specific tests skip rather than fail.** See `WindowsOnlyFactAttribute` for the
  DPAPI tests.

## Coding standards

Nullable reference types and implicit usings are enabled everywhere. Beyond that:

- Business logic never goes in XAML code-behind. The two accepted exceptions are reading a
  `PasswordBox`, which exposes no bindable property by design, and launching an external
  browser.
- Bind async commands with `AsyncRelayCommand`, not `RelayCommand`. The latter takes a
  synchronous delegate and will silently discard the returned task.
- I/O methods are async and accept a `CancellationToken`. No `.Result`, no `.Wait()`.
- Cancellation must reach the HTTP request. Setting a flag on a view model is not cancellation.

## Security expectations

IOC-X is a defensive analysis tool. It queries APIs and resolves DNS; it does not scan hosts,
probe services, execute anything it downloads, or attempt authentication anywhere. Keep it that
way. Specifically:

- Never log a credential.
- HTML-escape anything from a provider before it reaches a report.
- Treat every provider response as untrusted input.
- Every outbound request uses HTTPS and a timeout.
