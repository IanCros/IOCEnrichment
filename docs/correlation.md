# IOC-X Correlation Engine

## Overview

The correlation engine identifies meaningful relationships between IOCs based on provider observations. It transforms raw provider data into structured relationship graphs that can be used for investigation and analysis.

## Relationship Types

| Type | Description | Example |
|------|-------------|---------|
| ResolvesTo | Domain resolves to IP | example.com → 192.0.2.1 |
| HostedOn | URL hosted on domain | https://example.com/test → example.com |
| AssociatedWith | Generic association | IOC1 ↔ IOC2 |
| BelongsToAsn | IP belongs to ASN | 192.0.2.1 → AS12345 |
| HasNameserver | Domain has nameserver | example.com → ns1.example.com |
| HasMailServer | Domain has mail server | example.com → mx.example.com |
| ExposesService | IP exposes service | 192.0.2.1 → SSH on port 22 |
| AssociatedWithMalware | IOC linked to malware | IOC → Emotet |
| RelatedTo | Generic relationship | IOC1 ↔ IOC2 |

## Relationship Sources

### DNS

- A records → ResolvesTo (confidence: 90)
- PTR records → ResolvesTo (confidence: 90)

### Threat Intelligence (ThreatFox, URLhaus, VirusTotal)

- Malware family mentions → AssociatedWithMalware (confidence: 70)

### URL Providers

- Host field in URL data → HostedOn (confidence: 80)

### Shodan

- Open ports and services → ExposesService (confidence: 60)

### RDAP

- Nameservers → HasNameserver (confidence: 85)

## Confidence Levels

Confidence reflects the reliability of the relationship:

- 90-100: Authoritative data (e.g., DNS A records)
- 70-89: High confidence (e.g., RDAP nameservers)
- 50-69: Moderate confidence (e.g., Shodan service detection)
- Below 50: Inferred or speculative

## Duplicate Handling

The correlation engine deduplicates relationships using a composite key:

```
(source IOC ID, target IOC ID, relationship type)
```

Running the same investigation multiple times will not create duplicate relationships.

## Inference Rules

### DNS-Based Inference

When a domain resolves to an IP:
- Create ResolvesTo relationship
- If the IP has Shodan data, create ExposesService relationships
- If the IP appears in threat feeds, create AssociatedWithMalware relationships

### Malware-Based Inference

When malware is associated:
- Link to all IOCs in the same threat report
- Propagate risk through AssociatedWithMalware

### URL-Based Inference

When a URL is analyzed:
- Extract domain and create HostedOn relationship
- If the domain resolves, create ResolvesTo relationship

## Limitations

- Placeholder GUIDs are used for target IOCs that do not yet exist in the system.
- In a full implementation, relationships would be resolved to existing IOC entities.
- Correlation is based on normalized provider data, which may be incomplete.
- The engine does not create speculative relationships.