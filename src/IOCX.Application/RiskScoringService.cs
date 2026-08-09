namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Default implementation of risk scoring service.</summary>
public sealed class RiskScoringService : IRiskScoringService
{
    private const int MaxScore = 100;
    private const int MinScore = 0;

    public RiskAssessment CalculateRisk(Ioc ioc, IReadOnlyCollection<ProviderResult> results)
    {
        if (ioc == null) throw new ArgumentNullException(nameof(ioc));
        if (results == null) throw new ArgumentNullException(nameof(results));

        var evidence = new List<Evidence>();
        int score = 0;

        foreach (var result in results)
        {
            if (result.Status != ProviderStatus.Success || string.IsNullOrEmpty(result.NormalizedData))
                continue;

            var provider = result.ProviderName;
            var data = result.NormalizedData;

            // VirusTotal signals
            if (provider == "VirusTotal")
            {
                if (data.Contains("Malicious:"))
                {
                    var malicious = ExtractNumber(data, "Malicious:");
                    if (malicious > 0)
                    {
                        int contribution = Math.Min(25, malicious * 2);
                        score = Math.Min(MaxScore, score + contribution);
                        evidence.Add(new Evidence(EvidenceCategory.Reputation, $"VirusTotal reports {malicious} malicious detections.", EvidenceSeverity.High, contribution, provider, result.Timestamp));
                    }
                }
                if (data.Contains("Reputation:"))
                {
                    var reputation = ExtractNumber(data, "Reputation:");
                    if (reputation < 0)
                    {
                        int contribution = Math.Min(15, Math.Abs(reputation) / 10);
                        score = Math.Min(MaxScore, score + contribution);
                        evidence.Add(new Evidence(EvidenceCategory.Reputation, $"VirusTotal reputation score: {reputation}.", EvidenceSeverity.Medium, contribution, provider, result.Timestamp));
                    }
                }
            }

            // AbuseIPDB signals
            if (provider == "AbuseIPDB")
            {
                if (data.Contains("Abuse Confidence:"))
                {
                    var confidence = ExtractNumber(data, "Abuse Confidence:");
                    if (confidence >= 75)
                    {
                        int contribution = 20;
                        score = Math.Min(MaxScore, score + contribution);
                        evidence.Add(new Evidence(EvidenceCategory.AbuseReports, $"AbuseIPDB reports {confidence}% abuse confidence.", EvidenceSeverity.High, contribution, provider, result.Timestamp));
                    }
                    else if (confidence >= 50)
                    {
                        int contribution = 10;
                        score = Math.Min(MaxScore, score + contribution);
                        evidence.Add(new Evidence(EvidenceCategory.AbuseReports, $"AbuseIPDB reports {confidence}% abuse confidence.", EvidenceSeverity.Medium, contribution, provider, result.Timestamp));
                    }
                }
            }

            // ThreatFox signals
            if (provider == "ThreatFox" && data.Contains("Matches:"))
            {
                var matches = ExtractNumber(data, "Matches:");
                if (matches > 0)
                {
                    int contribution = Math.Min(20, matches * 5);
                    score = Math.Min(MaxScore, score + contribution);
                    evidence.Add(new Evidence(EvidenceCategory.ThreatIntelligence, $"ThreatFox identified {matches} matching IOC(s).", EvidenceSeverity.High, contribution, provider, result.Timestamp));
                }
            }

            // URLhaus signals
            if (provider == "URLhaus" && data.Contains("Matches:"))
            {
                var matches = ExtractNumber(data, "Matches:");
                if (matches > 0)
                {
                    int contribution = Math.Min(15, matches * 5);
                    score = Math.Min(MaxScore, score + contribution);
                    evidence.Add(new Evidence(EvidenceCategory.ThreatIntelligence, $"URLhaus identified {matches} matching malicious URL(s).", EvidenceSeverity.High, contribution, provider, result.Timestamp));
                }
            }

            // Provider agreement bonus
            if (provider == "VirusTotal" && data.Contains("Malicious:") && ExtractNumber(data, "Malicious:") > 0)
            {
                var otherMalicious = results.Count(r => r.ProviderName != "VirusTotal" && r.Status == ProviderStatus.Success && r.NormalizedData != null && (r.NormalizedData.Contains("Malicious:") || r.NormalizedData.Contains("malware") || r.NormalizedData.Contains("Malware")));
                if (otherMalicious > 0)
                {
                    int contribution = 10;
                    score = Math.Min(MaxScore, score + contribution);
                    evidence.Add(new Evidence(EvidenceCategory.ProviderAgreement, $"{otherMalicious + 1} independent providers indicate maliciousness.", EvidenceSeverity.High, contribution, "Multiple", result.Timestamp));
                }
            }
        }

        // Clamp score
        score = Math.Clamp(score, MinScore, MaxScore);

        var level = score switch
        {
            >= 80 => RiskLevel.Critical,
            >= 60 => RiskLevel.High,
            >= 40 => RiskLevel.Medium,
            >= 20 => RiskLevel.Low,
            _ => RiskLevel.Informational
        };

        return new RiskAssessment(ioc, score, level, evidence, DateTimeOffset.UtcNow);
    }

    private static int ExtractNumber(string text, string key)
    {
        var index = text.IndexOf(key, StringComparison.OrdinalIgnoreCase);
        if (index < 0) return 0;
        var start = index + key.Length;
        var remainder = text[start..].TrimStart();
        var numberText = new string(remainder.TakeWhile(c => char.IsDigit(c) || c == '-').ToArray());
        return int.TryParse(numberText, out var result) ? result : 0;
    }
}
