# IOC-X Scoring Engine

## Overview

The IOC-X scoring engine transforms raw provider results into meaningful risk and confidence assessments. It is deterministic, testable, and independent of any UI or provider-specific HTTP logic.

## Risk Score

### Scale

0-100, mapped to risk levels:

| Score | Level |
|-------|-------|
| 0-19 | Informational |
| 20-39 | Low |
| 40-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

### Calculation

The risk score aggregates evidence from multiple providers. Each piece of evidence includes:

- Category
- Description
- Severity
- Score contribution
- Provider
- Timestamp

Evidence is grouped by meaningful categories to avoid double-counting. For example, multiple VirusTotal signals related to the same underlying detection are consolidated.

### Provider Weights (Initial)

#### VirusTotal

- Malicious detections: up to +25 (2 points per detection, capped)
- Negative reputation: up to +15 (1 point per 10 reputation points, capped)

#### AbuseIPDB

- Abuse confidence >= 75%: +20
- Abuse confidence 50-74%: +10

#### ThreatFox

- Matching IOCs: up to +20 (5 points per match, capped)

#### URLhaus

- Matching malicious URLs: up to +15 (5 points per match, capped)

#### Provider Agreement

- Multiple independent providers indicating maliciousness: +10

### Score Cap

Final scores are clamped to 0-100 using a centralized normalization step.

## Confidence Score

### Scale

0-100%

### Calculation

Confidence reflects how reliable the assessment is, not how dangerous the IOC is.

Factors:

- Provider success rate: +0-20%
- High/Critical evidence items: +0-15%
- Provider agreement/corroboration: +0-10%
- Provider failures/timeouts: -0-15%
- No evidence found: -10%

Base confidence starts at 50%.

### Examples

- High risk (85) + 93% confidence = strong evidence from multiple sources
- High risk (78) + 38% confidence = limited or uncertain information

## Evidence

### Categories

- Reputation
- MalwareAssociation
- ThreatIntelligence
- AbuseReports
- Infrastructure
- Correlation
- Recency
- ProviderAgreement
- Registration
- Dns

### Severity

- Informational
- Low
- Medium
- High
- Critical

## Provider Failures

Provider failures affect confidence, not risk. A missing provider does not automatically reduce the risk score, but it reduces confidence because one intelligence source was unavailable.

Distinguish:

- "No evidence found" = provider returned no matches
- "Provider unavailable" = provider failed or timed out

## Freshness

Recent evidence is generally more relevant. Freshness is one factor in confidence calculation. Old evidence is not automatically discarded but contributes less to confidence.

## Limitations

- The scoring system provides an assessment, not absolute proof of maliciousness.
- False positives and false negatives are possible.
- Weights are configurable but require careful adjustment.
- The system only knows what providers report.