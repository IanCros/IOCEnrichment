namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Calculates risk assessments from provider results.</summary>
public interface IRiskScoringService
{
    /// <summary>Calculates a risk assessment for the specified IOC based on provider results.</summary>
    RiskAssessment CalculateRisk(Ioc ioc, IReadOnlyCollection<ProviderResult> results);
}

/// <summary>Calculates confidence assessments for analysis results.</summary>
public interface IConfidenceScoringService
{
    /// <summary>
    /// Calculates a confidence assessment based on provider results and risk assessment.
    /// </summary>
    ConfidenceAssessment CalculateConfidence(Ioc ioc, IReadOnlyCollection<ProviderResult> results, RiskAssessment riskAssessment);
}

/// <summary>Correlates IOCs based on provider observations.</summary>
public interface IIocCorrelationService
{
    /// <summary>Identifies relationships between IOCs based on provider results.</summary>
    IReadOnlyCollection<IocRelationship> Correlate(Ioc ioc, IReadOnlyCollection<ProviderResult> results);
}

/// <summary>Generates human-readable investigation summaries.</summary>
public interface IInvestigationSummaryService
{
    /// <summary>
    /// Generates an investigation summary based on risk assessment, confidence, and evidence.
    /// </summary>
    string GenerateSummary(RiskAssessment riskAssessment, ConfidenceAssessment confidenceAssessment, IReadOnlyCollection<Evidence> evidence);
}

/// <summary>Orchestrates the complete analysis pipeline for an investigation.</summary>
public interface IInvestigationAnalysisService
{
    /// <summary>Performs complete analysis on provider results for an IOC.</summary>
    Task<AnalysisResult> AnalyzeAsync(Ioc ioc, IReadOnlyCollection<ProviderResult> results, CancellationToken cancellationToken = default);
}

/// <summary>Represents the complete analysis result for an investigation.</summary>
public sealed record AnalysisResult(
    Ioc Ioc,
    RiskAssessment RiskAssessment,
    ConfidenceAssessment ConfidenceAssessment,
    IReadOnlyCollection<Evidence> Evidence,
    IReadOnlyCollection<IocRelationship> Relationships,
    string Summary,
    DateTimeOffset AnalyzedAt);
