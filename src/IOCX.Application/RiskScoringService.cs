namespace IOCX.Application;

using IOCX.Application.Configuration;
using IOCX.Domain;

/// <summary>Calculates an explainable 0-100 risk score from provider findings.</summary>
/// <remarks>
/// The engine is deliberately provider-agnostic. It reads only <see cref="ProviderFindings"/>
/// and never branches on a provider's name. Adding a provider therefore changes the score
/// only through the facts that provider reports, not through changes to this class.
/// Weights and band thresholds come from <see cref="ScoringOptions"/> so the model can be
/// retuned without a recompile. See <c>docs/scoring.md</c>.
/// </remarks>
public sealed class RiskScoringService : IRiskScoringService
{
    private const int MaxScore = 100;
    private const int MinScore = 0;

    private readonly ScoringOptions _options;

    public RiskScoringService(ScoringOptions? options = null)
    {
        _options = options ?? new ScoringOptions();
    }

    /// <inheritdoc />
    public RiskAssessment CalculateRisk(Ioc ioc, IReadOnlyCollection<ProviderResult> results)
    {
        ArgumentNullException.ThrowIfNull(ioc);
        ArgumentNullException.ThrowIfNull(results);

        var evidence = new List<Evidence>();
        var score = 0;

        var contributing = results
            .Where(r => r.Status == ProviderStatus.Success && r.Findings is not null)
            .ToList();

        foreach (var result in contributing)
        {
            var findings = result.Findings!;
            var provider = result.ProviderName;

            score = AddDetectionSignals(findings, provider, result.Timestamp, score, evidence);
            score = AddAbuseSignals(findings, provider, result.Timestamp, score, evidence);
            score = AddThreatMatchSignals(findings, provider, result.Timestamp, score, evidence);
        }

        score = AddMalwareAssociationSignal(contributing, score, evidence);
        score = AddCorroborationSignal(contributing, score, evidence);
        score = AddRecencySignal(contributing, score, evidence);

        score = Math.Clamp(score, MinScore, MaxScore);

        return new RiskAssessment(ioc, score, ToRiskLevel(score), evidence, DateTimeOffset.UtcNow);
    }

    /// <summary>Maps a numeric score onto its configured risk band.</summary>
    public RiskLevel ToRiskLevel(int score)
    {
        if (score >= _options.CriticalThreshold) return RiskLevel.Critical;
        if (score >= _options.HighThreshold) return RiskLevel.High;
        if (score >= _options.MediumThreshold) return RiskLevel.Medium;
        if (score >= _options.LowThreshold) return RiskLevel.Low;
        return RiskLevel.Informational;
    }

    private int AddDetectionSignals(
        ProviderFindings findings,
        string provider,
        DateTimeOffset timestamp,
        int score,
        List<Evidence> evidence)
    {
        if (findings.Detections is not { } detections)
        {
            return score;
        }

        if (detections.Malicious > 0)
        {
            var contribution = Math.Min(
                _options.MaxDetectionScore,
                detections.Malicious * _options.PerMaliciousDetection);

            score += contribution;

            var total = detections.TotalEngines;
            var description = total > 0
                ? $"{provider}: {detections.Malicious} of {total} engines classified the indicator as malicious."
                : $"{provider}: {detections.Malicious} engines classified the indicator as malicious.";

            evidence.Add(new Evidence(
                EvidenceCategory.Reputation,
                description,
                detections.Malicious >= 10 ? EvidenceSeverity.Critical : EvidenceSeverity.High,
                contribution,
                provider,
                timestamp));
        }

        if (detections.Reputation is { } reputation && reputation < 0)
        {
            var contribution = Math.Min(_options.MaxReputationScore, Math.Abs(reputation) / 10);
            if (contribution > 0)
            {
                score += contribution;
                evidence.Add(new Evidence(
                    EvidenceCategory.Reputation,
                    $"{provider}: community reputation is {reputation}.",
                    EvidenceSeverity.Medium,
                    contribution,
                    provider,
                    timestamp));
            }
        }

        return score;
    }

    private int AddAbuseSignals(
        ProviderFindings findings,
        string provider,
        DateTimeOffset timestamp,
        int score,
        List<Evidence> evidence)
    {
        if (findings.Abuse is not { } abuse)
        {
            return score;
        }

        var (contribution, severity) = abuse.ConfidencePercent switch
        {
            var c when c >= _options.HighAbuseConfidenceThreshold =>
                (_options.HighAbuseScore, EvidenceSeverity.High),
            var c when c >= _options.ModerateAbuseConfidenceThreshold =>
                (_options.ModerateAbuseScore, EvidenceSeverity.Medium),
            _ => (0, EvidenceSeverity.Informational)
        };

        if (contribution == 0)
        {
            return score;
        }

        score += contribution;

        var reportSuffix = abuse.TotalReports is { } reports and > 0
            ? $" across {reports} report(s)"
            : string.Empty;

        evidence.Add(new Evidence(
            EvidenceCategory.AbuseReports,
            $"{provider}: {abuse.ConfidencePercent}% abuse confidence{reportSuffix}.",
            severity,
            contribution,
            provider,
            timestamp));

        return score;
    }

    private int AddThreatMatchSignals(
        ProviderFindings findings,
        string provider,
        DateTimeOffset timestamp,
        int score,
        List<Evidence> evidence)
    {
        if (findings.ThreatMatches is not { } matches || matches.MatchCount <= 0)
        {
            return score;
        }

        var contribution = Math.Min(
            _options.MaxThreatMatchScore,
            matches.MatchCount * _options.PerThreatMatch);

        score += contribution;

        evidence.Add(new Evidence(
            EvidenceCategory.ThreatIntelligence,
            $"{provider}: {matches.MatchCount} threat intelligence match(es).",
            EvidenceSeverity.High,
            contribution,
            provider,
            timestamp));

        return score;
    }

    /// <summary>
    /// Adds a single malware-association signal, regardless of how many providers named a family.
    /// Scoring the association once keeps corroboration in the dedicated agreement signal.
    /// </summary>
    private int AddMalwareAssociationSignal(
        IReadOnlyList<ProviderResult> results,
        int score,
        List<Evidence> evidence)
    {
        var families = results
            .SelectMany(r => r.Findings!.ThreatMatches?.Families ?? Array.Empty<string>())
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (families.Count == 0)
        {
            return score;
        }

        var reporting = results
            .Where(r => r.Findings!.ThreatMatches?.Families.Count > 0)
            .Select(r => r.ProviderName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        score += _options.MalwareAssociationScore;

        evidence.Add(new Evidence(
            EvidenceCategory.MalwareAssociation,
            $"Associated with malware family/families: {string.Join(", ", families)}.",
            EvidenceSeverity.Critical,
            _options.MalwareAssociationScore,
            reporting.Count == 1 ? reporting[0] : "Multiple",
            DateTimeOffset.UtcNow));

        return score;
    }

    /// <summary>
    /// Rewards agreement between independent providers. A single source can be wrong, so
    /// corroboration is scored on its own rather than folded into the raw signals.
    /// </summary>
    private int AddCorroborationSignal(
        IReadOnlyList<ProviderResult> results,
        int score,
        List<Evidence> evidence)
    {
        var incriminating = results
            .Where(r => IndicatesMalicious(r.Findings!))
            .Select(r => r.ProviderName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (incriminating.Count < 2)
        {
            return score;
        }

        score += _options.ProviderAgreementScore;

        evidence.Add(new Evidence(
            EvidenceCategory.ProviderAgreement,
            $"{incriminating.Count} independent providers reported adverse findings: {string.Join(", ", incriminating)}.",
            EvidenceSeverity.High,
            _options.ProviderAgreementScore,
            "Multiple",
            DateTimeOffset.UtcNow));

        return score;
    }

    private int AddRecencySignal(
        IReadOnlyList<ProviderResult> results,
        int score,
        List<Evidence> evidence)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-_options.RecentActivityWindowDays);

        var mostRecent = results
            .Where(r => IndicatesMalicious(r.Findings!))
            .Select(r => r.Findings!.LastActivityAt)
            .Where(t => t is not null)
            .Select(t => t!.Value)
            .DefaultIfEmpty()
            .Max();

        if (mostRecent == default || mostRecent < cutoff)
        {
            return score;
        }

        score += _options.RecentActivityScore;

        evidence.Add(new Evidence(
            EvidenceCategory.Recency,
            $"Adverse activity observed on {mostRecent:yyyy-MM-dd}, within the last {_options.RecentActivityWindowDays} days.",
            EvidenceSeverity.Medium,
            _options.RecentActivityScore,
            "Multiple",
            DateTimeOffset.UtcNow));

        return score;
    }

    /// <summary>
    /// Determines whether a provider's findings point at malicious activity, without
    /// reference to which provider produced them.
    /// </summary>
    private bool IndicatesMalicious(ProviderFindings findings) =>
        findings.Detections?.Malicious > 0
        || findings.Abuse?.ConfidencePercent >= _options.ModerateAbuseConfidenceThreshold
        || findings.ThreatMatches?.MatchCount > 0;
}
