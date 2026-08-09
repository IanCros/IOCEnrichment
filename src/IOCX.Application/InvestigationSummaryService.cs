namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Default implementation of investigation summary service.</summary>
public sealed class InvestigationSummaryService : IInvestigationSummaryService
{
    public string GenerateSummary(RiskAssessment riskAssessment, ConfidenceAssessment confidenceAssessment, IReadOnlyCollection<Evidence> evidence)
    {
        if (riskAssessment == null) throw new ArgumentNullException(nameof(riskAssessment));
        if (confidenceAssessment == null) throw new ArgumentNullException(nameof(confidenceAssessment));

        var sb = new System.Text.StringBuilder();

        sb.AppendLine($"Risk Assessment: {riskAssessment.Level} ({riskAssessment.Score}/100)");
        sb.AppendLine($"Confidence: {confidenceAssessment.Score}%");
        sb.AppendLine();

        if (evidence.Any())
        {
            sb.AppendLine("Key Evidence:");
            foreach (var e in evidence.OrderByDescending(e => e.ScoreContribution).Take(5))
            {
                sb.AppendLine($"  +{e.ScoreContribution} {e.Category}: {e.Description} [{e.Severity}] ({e.Provider})");
            }
        }
        else
        {
            sb.AppendLine("No threat intelligence evidence was identified by available sources.");
        }

        sb.AppendLine();
        sb.AppendLine($"Analyzed at: {riskAssessment.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");

        return sb.ToString().TrimEnd();
    }
}
