# Risk and Confidence Scoring

IOC-X produces two independent numbers for every investigation. Reading them together is the
point: they answer different questions and either one alone is misleading.

| Score | Question it answers | Range |
| --- | --- | --- |
| Risk | How adverse is what we found? | 0–100 |
| Confidence | How much should we trust that finding? | 0–100 |

A HIGH risk score at 30% confidence means one source saw something serious and nothing
corroborated it. The same risk score at 95% confidence means several independent sources agree.
Those two results warrant different actions, which is why the model refuses to collapse them
into a single number.

## How risk is calculated

The scoring engine reads only [`ProviderFindings`](../src/IOCX.Domain/ProviderFindings.cs) — a
provider-agnostic record of facts. It never inspects a provider's name and never parses display
text. Adding a new provider therefore changes the score only through the facts that provider
reports; it requires no change to
[`RiskScoringService`](../src/IOCX.Application/RiskScoringService.cs).

Signals are additive, each is individually capped, and the total is clamped to 100.

### Per-provider signals

These are evaluated once for each provider that returned findings.

| Signal | Weight | Cap | Source field |
| --- | --- | --- | --- |
| Malicious detections | 2 per engine | 25 | `Detections.Malicious` |
| Negative community reputation | 1 per 10 points | 15 | `Detections.Reputation` |
| Abuse confidence ≥ 75% | 20 | — | `Abuse.ConfidencePercent` |
| Abuse confidence 50–74% | 10 | — | `Abuse.ConfidencePercent` |
| Threat-feed matches | 5 per match | 20 | `ThreatMatches.MatchCount` |

### Investigation-wide signals

These are evaluated once for the whole investigation, no matter how many providers contributed.

| Signal | Weight | Condition |
| --- | --- | --- |
| Malware association | 25 | Any provider named a malware family |
| Independent corroboration | 10 | Two or more providers reported adverse findings |
| Recent activity | 10 | Adverse activity observed within the last 30 days |

Malware association is scored **once** rather than per provider. Two feeds naming the same family
is corroboration, which the agreement signal already rewards; charging the association weight
twice would double-count the same underlying fact.

"Adverse findings" is defined without reference to any provider: malicious detections above zero,
abuse confidence at or above the moderate threshold, or at least one threat-feed match.

### Risk bands

| Score | Level |
| --- | --- |
| 0–19 | Informational |
| 20–39 | Low |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

Every weight, cap, and band boundary in this document is a default, configurable under
`Scoring` in `appsettings.json` or from the Settings screen. See
[`ScoringOptions`](../src/IOCX.Application/Configuration/IocxOptions.cs).

## Evidence

The engine emits an `Evidence` item for every signal it applies, recording the category,
a human-readable description, the severity, the points contributed, and the reporting provider.

The contributions of all evidence items sum exactly to the risk score — this is enforced by a
test. There is no hidden term: if the score is 62, the evidence list explains all 62 points.

## How confidence is calculated

Confidence starts at 50 and is adjusted by how well-supported the assessment is:

| Factor | Effect |
| --- | --- |
| Provider success rate | up to +20, proportional to the share that answered |
| High or critical evidence items | +3 each, capped at +15 |
| Independent corroboration present | +5, capped at +10 |
| Providers that failed or were unavailable | −3 each, capped at −15 |
| No evidence found at all | −10 |

The result is clamped to 0–100. Note that confidence deliberately falls when providers fail: an
assessment built on two sources out of seven is less trustworthy than the same assessment built
on all seven, even when the risk score is identical.

## Limitations

Read the score as an analytical aid, not a verdict. Specific things it cannot do:

**It cannot see what no provider reported.** An indicator scoring 0 has not been cleared; it
means the configured sources had nothing to say. Newly registered infrastructure is routinely
invisible to every feed for its first days of use.

**Threat intelligence goes stale.** A compromised host that has since been cleaned may carry
feed entries for months. The recency signal reduces but does not eliminate this: it withholds
the recency bonus for old activity, yet the underlying match still scores.

**Shared infrastructure inflates scores.** A CDN edge address, a shared hosting IP, or a URL
shortener domain can accumulate adverse reports caused by other tenants. Infrastructure facts
in the Infrastructure tab are usually the fastest way to spot this.

**Corroboration can be illusory.** Providers are treated as independent sources, but feeds
partly derive from one another. Two feeds agreeing is weaker evidence than the +10 weight
implies when both ultimately drew on the same report.

**Absence of a key silently narrows coverage.** A provider without credentials is skipped, not
failed, so it does not depress confidence the way a timeout does. Check the Settings screen to
confirm which providers actually ran.

**The weights are judgement, not measurement.** They were chosen to produce sensible orderings,
not calibrated against a labelled corpus. Retune them for your environment; that is why they
are configurable.

Treat a high score as a reason to investigate further, and a low score as an absence of evidence
rather than evidence of absence.
