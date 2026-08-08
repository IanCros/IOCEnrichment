# IOC-X Providers

This document describes the threat intelligence providers implemented in IOC-X.

## Overview

IOC-X currently supports three threat intelligence providers:

1. **VirusTotal**
2. **AbuseIPDB**
3. **ThreatFox**

All providers implement the `IEnrichmentProvider` interface and integrate with the existing HTTP infrastructure, rate limiting, caching, and enrichment orchestration.

---

## VirusTotal

### Supported IOC Types

| Type | Supported |
|------|-----------|
| IPv4 | Ã¢Å“â€¦ |
| IPv6 | Ã¢Å“â€¦ |
| Domain | Ã¢Å“â€¦ |
| URL | Ã¢Å“â€¦ |
| MD5 | Ã¢Å“â€¦ |
| SHA1 | Ã¢Å“â€¦ |
| SHA256 | Ã¢Å“â€¦ |
| Email | Ã¢ÂÅ’ |

### Required Configuration

Set the API key via the `VT_API_KEY` environment variable. The API key is never hardcoded, committed, logged, or included in exceptions.

### Data Collected

For each IOC type, the provider extracts:

- Malicious count
- Suspicious count
- Harmless count
- Undetected count
- Reputation score (where available)

### API Endpoints

- **IP addresses**: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- **Domains**: `https://www.virustotal.com/api/v3/domains/{domain}`
- **URLs**: `https://www.virustotal.com/api/v3/urls/{base64}` (base64-encoded URL)
- **File hashes**: `https://www.virustotal.com/api/v3/files/{hash}`

### Error Handling

| HTTP Status | Mapping |
|-------------|---------|
| 200 | Success |
| 400 | Error |
| 401/403 | Unauthorized |
| 404 | Unavailable (not found) |
| 429 | RateLimited |
| 500+ | Unavailable |
| Timeout | Timeout |
| Malformed JSON | InvalidResponse |

### Rate Limiting

Rate limiting uses the shared `RateLimiter` infrastructure. HTTP 429 responses are mapped to `ProviderStatus.RateLimited`. No aggressive retry loops are used.

### Limitations

- Free tier has strict rate limits.
- URL queries use base64-encoded value which may need a `url_id` for lookups.
- Analysis stats represent the latest scan, not historical data.

---

## AbuseIPDB

### Supported IOC Types

| Type | Supported |
|------|-----------|
| IPv4 | Ã¢Å“â€¦ |
| IPv6 | Ã¢Å“â€¦ |
| Domain | Ã¢ÂÅ’ |
| URL | Ã¢ÂÅ’ |
| MD5 | Ã¢ÂÅ’ |
| SHA1 | Ã¢ÂÅ’ |
| SHA256 | Ã¢ÂÅ’ |
| Email | Ã¢ÂÅ’ |

### Required Configuration

Set the API key via the `ABUSEIPDB_API_KEY` environment variable. The API key is never hardcoded, committed, logged, or included in exceptions.

### Data Collected

- Abuse confidence score
- Country code
- ISP
- Domain
- Public/private status
- Tor status
- ASN (where available)
- ASN organization (where available)

### API Endpoints

- **IP check**: `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`

### Error Handling

| HTTP Status | Mapping |
|-------------|---------|
| 200 | Success |
| 400 | Error |
| 401/403 | Unauthorized |
| 404 | Unavailable (not found) |
| 429 | RateLimited |
| 500+ | Unavailable |
| Timeout | Timeout |
| Malformed JSON | InvalidResponse |

### Rate Limiting

Rate limiting uses the shared `RateLimiter` infrastructure. HTTP 429 responses are mapped to `ProviderStatus.RateLimited`.

### Limitations

- Only supports IP address queries (IPv4 and IPv6).
- Free tier is limited to 500 requests per day.
- `maxAgeInDays=90` limits the report age considered.

---

## ThreatFox

### Supported IOC Types

| Type | Supported |
|------|-----------|
| IPv4 | Ã¢Å“â€¦ |
| IPv6 | Ã¢Å“â€¦ |
| Domain | Ã¢Å“â€¦ |
| URL | Ã¢Å“â€¦ |
| MD5 | Ã¢Å“â€¦ |
| SHA1 | Ã¢Å“â€¦ |
| SHA256 | Ã¢Å“â€¦ |
| Email | Ã¢ÂÅ’ |

### Authentication

ThreatFox API does not require authentication for search queries. The endpoint is publicly accessible.

### Data Collected

For each match:

- IOC value
- IOC type
- Malware family
- Confidence level
- First seen timestamp
- Last seen timestamp

Multiple matches are preserved Ã¢â‚¬â€ the provider returns all observations rather than just the first.

### API Endpoints

- **Search IOC**: `https://threatfox-api.abuse.ch/api/v1/` (POST with `query=search_ioc`)

### Error Handling

| HTTP Status | Mapping |
|-------------|---------|
| 200 | Success |
| 401/403 | Unauthorized |
| 429 | RateLimited |
| 500+ | Unavailable |
| Timeout | Timeout |
| Malformed JSON | InvalidResponse |
| `query_status: no_result` | Success (no matches) |
| `query_status: invalid_request` | Error |

### Rate Limiting

Rate limiting uses the shared `RateLimiter` infrastructure. HTTP 429 responses are mapped to `ProviderStatus.RateLimited`.

### Limitations

- Returns data shared by the ThreatFox community; coverage varies.
- Hash search results depend on community submissions.
- The public API may have query frequency limits.

---

## Provider Isolation

Each provider runs independently and concurrently via the `EnrichmentService`. A failure in one provider (e.g., rate limiter, server error, timeout) does not prevent other providers from completing successfully.

## Caching

Provider results are cached using the Stage 2 caching infrastructure. Cache keys are structured as:

```
{ProviderName}:{NormalizedIoc}
```

For example:
- `VirusTotal:example.com`
- `AbuseIPDB:192.0.2.1`
- `ThreatFox:example.com`

Cached results respect the configured TTL and are only considered valid if not expired.

## Security

- API keys are read from environment variables only.
- Keys are never committed to the repository.
- Keys are never logged or included in exception messages.
- Keys are never included in test fixtures.
---

## Shodan

### Supported IOC Types

| Type | Supported |
|------|-----------|
| IPv4 | âœ… |
| IPv6 | âœ… |
| Domain | âŒ |
| URL | âŒ |
| MD5/SHA1/SHA256 | âŒ |
| Email | âŒ |

### Required Configuration

Set the API key via the `SHODAN_API_KEY` environment variable. Never hardcode or commit API keys.

### Data Collected

- IP address
- Organization
- ISP
- ASN
- Country, city, region
- Hostnames and domains
- Open ports
- Services with products and versions
- Last update timestamp

### API Endpoints

- **Host lookup**: `https://api.shodan.io/shodan/host/{ip}?key={api_key}`

### Error Handling

| HTTP Status | Mapping |
|-------------|---------|
| 401/403 | Unauthorized |
| 404 | Unavailable |
| 429 | RateLimited |
| 500+ | Unavailable |
| Timeout | Timeout |
| Malformed JSON | InvalidResponse |

### Passive Behavior

IOC-X only queries Shodan's existing intelligence. No active scanning or exploitation is performed.

### Limitations

- Requires a Shodan API key.
- Free tier has strict request quotas.
- IPv6 support depends on Shodan's current coverage.

---

## URLhaus

### Supported IOC Types

| Type | Supported |
|------|-----------|
| URL | âœ… |
| Domain | âœ… |
| IPv4 | âœ… |
| IPv6 | âœ… |
| MD5/SHA1/SHA256 | âŒ |
| Email | âŒ |

### Data Collected

- URL
- URL status
- Threat type
- Malware family
- Date added and last online
- Reporter
- Tags
- Host and IP address

### API Endpoints

- **URL lookup**: `https://urlhaus-api.abuse.ch/v1/url/` (POST)

### Behavior

IOC-X is an intelligence consumer. It never downloads or executes malware, and never interacts with discovered malicious URLs beyond the documented intelligence API.

### Limitations

- Coverage depends on community submissions.
- URLhaus may return no results for recently observed or unlisted indicators.

---

## DNS

### Supported IOC Types

| Type | Supported |
|------|-----------|
| Domain | âœ… |
| IPv4 | âœ… (PTR) |
| IPv6 | âœ… (PTR) |
| URL/MD5/SHA1/SHA256 | âŒ |
| Email | âŒ |

### Record Types Collected (passive)

- A records
- PTR records (for IP addresses)
- Host entry resolution providing address lists and CNAME aliases

### Passive Safety

DNS enrichment is strictly passive:

- No brute forcing
- No subdomain enumeration
- No zone transfers
- No aggressive enumeration
- No scanning

Only the requested IOC or explicitly related records are resolved.

### Error Handling

- NXDOMAIN â†’ reported in result, not a crash
- Timeout â†’ Timeout status
- DNS failure â†’ Error status
- No records â†’ Success with "no records found"

### Limitations

- Uses the system DNS resolver via an `IDnsResolver` abstraction.
- Does not collect MX/NS/TXT records directly in the current implementation (uses host entry resolution).
- Results depend on the local DNS environment.

---

## RDAP

### Supported IOC Types

| Type | Supported |
|------|-----------|
| Domain | âœ… |
| IPv4/IPv6 | âŒ |
| URL/MD5/SHA1/SHA256 | âŒ |
| Email | âŒ |

### Data Collected

- Domain handle
- Registrar (where publicly available)
- Registration date
- Last changed date
- Nameservers
- Domain statuses

### API Endpoints

- **Domain lookup** (bootstrap): `https://rdap.org/domain/{domain}`

### Privacy Considerations

- Privacy-redacted fields are simply omitted.
- IOC-X never attempts to circumvent privacy protections.

### Limitations

- Only domain lookups are supported.
- Depends on public RDAP bootstrap availability.
- Registration expiration dates may not be exposed by all registries (parsed from "expiration" event where available).
---

## Shodan

### Supported IOC Types

| Type | Supported |
|------|-----------|
| IPv4 | ✅ |
| IPv6 | ✅ |
| Domain | ❌ |
| URL | ❌ |
| MD5/SHA1/SHA256 | ❌ |
| Email | ❌ |

### Required Configuration

Set the API key via the `SHODAN_API_KEY` environment variable. Never hardcode or commit API keys.

### Data Collected

- IP address
- Organization
- ISP
- ASN
- Country, city, region
- Hostnames and domains
- Open ports
- Services with products and versions
- Last update timestamp

### API Endpoints

- **Host lookup**: `https://api.shodan.io/shodan/host/{ip}?key={api_key}`

### Error Handling

| HTTP Status | Mapping |
|-------------|---------|
| 401/403 | Unauthorized |
| 404 | Unavailable |
| 429 | RateLimited |
| 500+ | Unavailable |
| Timeout | Timeout |
| Malformed JSON | InvalidResponse |

### Passive Behavior

IOC-X only queries Shodan's existing intelligence. No active scanning or exploitation is performed.

### Limitations

- Requires a Shodan API key.
- Free tier has strict request quotas.
- IPv6 support depends on Shodan's current coverage.

---

## URLhaus

### Supported IOC Types

| Type | Supported |
|------|-----------|
| URL | ✅ |
| Domain | ✅ |
| IPv4 | ✅ |
| IPv6 | ✅ |
| MD5/SHA1/SHA256 | ❌ |
| Email | ❌ |

### Data Collected

- URL
- URL status
- Threat type
- Malware family
- Date added and last online
- Reporter
- Tags
- Host and IP address

### API Endpoints

- **URL lookup**: `https://urlhaus-api.abuse.ch/v1/url/` (POST)

### Behavior

IOC-X is an intelligence consumer. It never downloads or executes malware, and never interacts with discovered malicious URLs beyond the documented intelligence API.

### Limitations

- Coverage depends on community submissions.
- URLhaus may return no results for recently observed or unlisted indicators.

---

## DNS

### Supported IOC Types

| Type | Supported |
|------|-----------|
| Domain | ✅ |
| IPv4 | ✅ (PTR) |
| IPv6 | ✅ (PTR) |
| URL/MD5/SHA1/SHA256 | ❌ |
| Email | ❌ |

### Record Types Collected (passive)

- A records
- PTR records (for IP addresses)
- Host entry resolution providing address lists and CNAME aliases

### Passive Safety

DNS enrichment is strictly passive:

- No brute forcing
- No subdomain enumeration
- No zone transfers
- No aggressive enumeration
- No scanning

Only the requested IOC or explicitly related records are resolved.

### Error Handling

- NXDOMAIN → reported in result, not a crash
- Timeout → Timeout status
- DNS failure → Error status
- No records → Success with "no records found"

### Limitations

- Uses the system DNS resolver via an `IDnsResolver` abstraction.
- Does not collect MX/NS/TXT records directly in the current implementation (uses host entry resolution).
- Results depend on the local DNS environment.

---

## RDAP

### Supported IOC Types

| Type | Supported |
|------|-----------|
| Domain | ✅ |
| IPv4/IPv6 | ❌ |
| URL/MD5/SHA1/SHA256 | ❌ |
| Email | ❌ |

### Data Collected

- Domain handle
- Registrar (where publicly available)
- Registration date
- Last changed date
- Nameservers
- Domain statuses

### API Endpoints

- **Domain lookup** (bootstrap): `https://rdap.org/domain/{domain}`

### Privacy Considerations

- Privacy-redacted fields are simply omitted.
- IOC-X never attempts to circumvent privacy protections.

### Limitations

- Only domain lookups are supported.
- Depends on public RDAP bootstrap availability.
- Registration expiration dates may not be exposed by all registries.