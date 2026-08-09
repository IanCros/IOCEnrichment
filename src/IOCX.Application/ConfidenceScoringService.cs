namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Default implementation of confidence scoring service.</summary>
public sealed class ConfidenceScoringService : IConfidenceScoringService
{
    public ConfidenceAssessment CalculateConfidence(Ioc ioc, IReadOnlyCollection<ProviderResult> results, RiskAssessment riskAssessment)
    {
        if (ioc == null) throw new ArgumentNullException(nameof(ioc));
        if (results == null) throw new ArgumentNullException(nameof(results));
        if (riskAssessment == null) throw new ArgumentNullException(nameof(riskAssessment));

        int totalProviders = results.Count;
        int successfulProviders = results.Count(r => r.Status == ProviderStatus.Success);
        int failedProviders = totalProviders - successfulProviders;

        // Base confidence starts at 50
        int confidence = 50;

        var reasons = new List<string>();

        // Adjust based on provider success rate
        if (totalProviders > 0)
        {
            double successRate = (double)successfulProviders / totalProviders;
            confidence += (int)(successRate * 20);
            reasons.Add($"Provider success rate: {successfulProviders}/{totalProviders}");
        }

        // Adjust based on evidence quality
        if (riskAssessment.Evidence.Any())
        {
            var highOrCritical = riskAssessment.Evidence.Count(e => e.Severity == EvidenceSeverity.High || e.Severity == EvidenceSeverity.Critical);
            confidence += Math.Min(15, highOrCritical * 3);
            reasons.Add($"High/Critical evidence items: {highOrCritical}");
        }

        // Adjust based on provider agreement
        var agreementCount = riskAssessment.Evidence.Count(e => e.Category == EvidenceCategory.ProviderAgreement);
        if (agreementCount > 0)
        {
            confidence += Math.Min(10, agreementCount * 5);
            reasons.Add("Independent provider corroboration detected.");
        }

        // Penalty for provider failures/timeouts
        if (failedProviders > 0)
        {
            confidence -= Math.Min(15, failedProviders * 3);
            reasons.Add($"{failedProviders} provider(s) failed or were unavailable.");
        }

        // Penalty for no evidence found
        if (!riskAssessment.Evidence.Any())
        {
            confidence -= 10;
            reasons.Add("No threat intelligence evidence found.");
        }

        // Clamp confidence to 0-100
        confidence = Math.Clamp(confidence, 0, 100);

        string reason = string.Join(" ", reasons);
        if (string.IsNullOrWhiteSpace(reason))
        {
            reason = "Limited evidence available for confidence assessment.";
        }

        return new ConfidenceAssessment(confidence, reason);
    }
}
