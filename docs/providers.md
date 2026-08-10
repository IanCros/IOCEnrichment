# Intelligence Providers

IOC-X queries seven providers. Each one is an independent implementation of
`IEnrichmentProvider`; the enrichment core knows nothing about any of them beyond that
interface. Adding or removing a provider changes no other code.

Provider metadata lives in one place,
[`ProviderCatalog`](../src/IOCX.Application/Providers/ProviderCatalog.cs), which drives
dependency injection, the Settings screen, and the Dashboard health list alike.

## Summary

| Provider | Credential | IPv4/IPv6 | Domain | URL | Hashes | Email |
| --- | --- | :-: | :-: | :-: | :-: | :-: |
| VirusTotal | `VT_API_KEY` | yes | yes | yes | yes | no |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | yes | no | no | no | no |
| Shodan | `SHODAN_API_KEY` | yes | no | no | no | no |
| ThreatFox | `ABUSECH_AUTH_KEY` | yes | yes | yes | yes | no |
| URLhaus | `ABUSECH_AUTH_KEY` | yes | yes | yes | no | no |
| DNS | none | yes | yes | no | no | no |
| RDAP | none | yes | yes | no | no | no |

This table mirrors `ProviderCatalog`, and a test asserts the catalog matches each provider's
`Supports` method, so the two cannot drift apart silently.

A provider is queried only when it is enabled **and** its credential is available. Otherwise it
is skipped and reported as "Not configured" or "Disabled" — it never fails the investigation.

Rate-limit defaults are deliberately conservative, chosen to stay inside free-tier allowances
rather than to match each service's published ceiling. Verify current limits against the linked
documentation before raising them.

---

## VirusTotal

Aggregated verdicts from many antivirus engines and URL scanners.

- **Docs:** <https://docs.virustotal.com/reference/overview>
- **Auth:** `x-apikey` request header. Free key from your VirusTotal account page.
- **Default budget:** 4 requests per 60 seconds. The public tier is quota-limited per day as
  well as per minute; a burst of bulk analysis will exhaust it.

**Endpoints used**

| IOC type | Endpoint |
| --- | --- |
| IPv4, IPv6 | `/api/v3/ip_addresses/{ip}` |
| Domain | `/api/v3/domains/{domain}` |
| URL | `/api/v3/urls/{base64url}` |
| MD5, SHA-1, SHA-256 | `/api/v3/files/{hash}` |

**Fields extracted into `ProviderFindings.Detections`:** malicious, suspicious, harmless, and
undetected engine counts; community reputation; last analysis timestamp.

**Scoring impact:** malicious detections and negative reputation. See
[scoring.md](scoring.md).

---

## AbuseIPDB

Community-reported abuse history and a confidence rating for IP addresses.

- **Docs:** <https://docs.abuseipdb.com/>
- **Auth:** `Key` request header.
- **Default budget:** 4 requests per 15 seconds. The free tier is also capped per day.
- **Endpoint:** `/api/v2/check?ipAddress={ip}&maxAgeInDays=90`

**Fields extracted into `ProviderFindings.Abuse` and `.Infrastructure`:** abuse confidence
percentage, total report count, last reported timestamp, usage type, country, ISP, ASN. Any
domain reported for the address becomes a related indicator.

**Scoring impact:** abuse confidence, banded at 50% and 75%.

---

## Shodan

Previously observed open ports, services, and banners for an address.

- **Docs:** <https://developer.shodan.io/api>
- **Auth:** `key` query-string parameter, not a header.
- **Default budget:** 3 requests per 15 seconds.
- **Endpoint:** `/shodan/host/{ip}`

**Fields extracted into `ProviderFindings.Infrastructure`:** organization, ASN, country, city,
hostnames, open ports, and per-port product and version.

**Scoring impact:** none directly. Infrastructure facts are context for the analyst and inputs
to correlation, not risk signals — a host having open ports is not itself adverse.

**Note:** Shodan reports what its own scanning previously observed. IOC-X never scans anything.

---

## ThreatFox

abuse.ch feed of indicators tied to named malware families.

- **Docs:** <https://threatfox.abuse.ch/api/>
- **Auth:** `Auth-Key` request header. Free key from <https://auth.abuse.ch/>; the same key
  also enables URLhaus.
- **Default budget:** 1 request per 15 seconds, per abuse.ch fair-use expectations.
- **Endpoint:** `POST /api/v1/` with `{"query":"search_ioc","search_term":"..."}`

**Fields extracted into `ProviderFindings.ThreatMatches`:** match count, malware families,
tags, first-seen and last-seen timestamps.

**Scoring impact:** match count, plus the malware-association signal when a family is named.

**Note:** abuse.ch previously served this API without authentication. Unauthenticated requests
now return HTTP 401.

---

## URLhaus

abuse.ch feed of URLs distributing malware payloads.

- **Docs:** <https://urlhaus.abuse.ch/api/>
- **Auth:** `Auth-Key` request header, same key as ThreatFox.
- **Default budget:** 1 request per 15 seconds.
- **Endpoint:** `POST /v1/url/`

**Fields extracted into `ProviderFindings.ThreatMatches` and `.Related`:** match count, URL
status (online/offline), threat classification, malware family, tags, date added, reporter.
The hosting IP and host become related indicators.

**Scoring impact:** match count, plus the malware-association signal when a family is named.

---

## DNS

Passive resolution using the system resolver.

- **Auth:** none.
- **Default budget:** 10 requests per 15 seconds.
- **Record types:** A, AAAA, CNAME, MX, NS, TXT, and PTR for addresses.

**Fields extracted into `ProviderFindings.Dns`:** the resolved records, grouped by type.

**Scoring impact:** none. Resolution is used for correlation — a domain resolving to an address
creates a `ResolvesTo` relationship — not as a risk signal.

**Note:** this is ordinary resolution of the queried name only. IOC-X performs no zone transfer,
brute-force subdomain enumeration, or other aggressive lookups.

**Failure behaviour:** NXDOMAIN is reported as a successful query with no records rather than as
an error, because "this name does not resolve" is a finding.

---

## RDAP

Registration data for domains, from the RDAP successor to WHOIS.

- **Docs:** <https://about.rdap.org/>
- **Auth:** none.
- **Default budget:** 5 requests per 15 seconds.
- **Endpoints:** `https://rdap.org/domain/{domain}` for names and
  `https://rdap.org/ip/{address}` for addresses. Both redirect to the authoritative registry.

**Fields extracted for domains, into `ProviderFindings.Registration`:** registrar, registration
and update dates, nameservers, EPP status codes, and whether contact details were redacted.

**Fields extracted for addresses, into `ProviderFindings.Infrastructure`:** allocation handle,
network name, address range, owning organization, and country. This is the only source of
ownership context when Shodan and AbuseIPDB are not configured.

**Scoring impact:** none currently. Domain age is available via `RegistrationFacts.AgeAt` and is
a natural future signal, since newly registered domains are disproportionately malicious.

**Privacy:** most registrars redact registrant contact details under GDPR. IOC-X records that
redaction occurred and makes no attempt to circumvent it.

**Note:** RDAP registries reject requests that omit a `User-Agent`. IOC-X identifies itself on
every request; removing that header causes HTTP 403 from several registries.

---

## Failure behaviour

Every provider maps its outcome onto a `ProviderStatus`, and a failure in one never aborts the
investigation:

| Condition | Status |
| --- | --- |
| 200 with parseable body | `Success` |
| 401, 403 | `Unauthorized` |
| 404 | `Unavailable` |
| 429 | `RateLimited` |
| 5xx | `Unavailable` |
| Request timed out or cancelled | `Timeout` |
| Body present but unparseable | `InvalidResponse` |
| IOC type the provider cannot answer for | `Unsupported` |
| Provider disabled or missing its key | never queried |

Failures are persisted alongside successes, because knowing that a provider timed out is part of
interpreting the confidence score. Confidence falls as providers fail; risk does not rise.

## Caching

Responses are cached in SQLite keyed by provider plus normalized IOC. Before querying, IOC-X
checks for a fresh entry and reuses it, which both respects provider quotas and avoids
re-disclosing an indicator to a third party unnecessarily. The default lifetime is 60 minutes,
configurable globally or per provider.

## Isolation

Provider-specific shapes never escape the provider. Each one translates its own API response
into `ProviderFindings`, and everything downstream — scoring, correlation, reporting — reads
only that. This is what allows the scoring engine to contain no provider names at all.

`ProviderResult.NormalizedData` carries a human-readable summary for display. It is presentation
only; nothing parses it back into data.
