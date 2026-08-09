namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Default implementation of investigation analysis orchestration service.</summary>
public sealed class InvestigationAnalysisService : IInvestigationAnalysisService
{
    private readonly IRiskScoringService _riskScoringService;
    private readonly IConfidenceScoringService _confidenceScoringService;
    private readonly IIocCorrelationService _correlationService;
    private readonly IInvestigationSummaryService _summaryService;

    public InvestigationAnalysisService(
        IRiskScoringService riskScoringService,
        IConfidenceScoringService confidenceScoringService,
        IIocCorrelationService correlationService,
        IInvestigationSummaryService summaryService)
    {
        _riskScoringService = riskScoringService ?? throw new ArgumentNullException(nameof(riskScoringService));
        _confidenceScoringService = confidenceScoringService ?? throw new ArgumentNullException(nameof(confidenceScoringService));
        _correlationService = correlationService ?? throw new ArgumentNullException(nameof(correlationService));
        _summaryService = summaryService ?? throw new ArgumentNullException(nameof(summaryService));
    }

    public Task<AnalysisResult> AnalyzeAsync(Ioc ioc, IReadOnlyCollection<ProviderResult> results, CancellationToken cancellationToken = default)
    {
        if (ioc == null) throw new ArgumentNullException(nameof(ioc));
        if (results == null) throw new ArgumentNullException(nameof(results));

        cancellationToken.ThrowIfCancellationRequested();

        // Calculate risk assessment
        var riskAssessment = _riskScoringService.CalculateRisk(ioc, results);

        // Calculate confidence assessment
        var confidenceAssessment = _confidenceScoringService.CalculateConfidence(ioc, results, riskAssessment);

        // Collect all evidence
        var evidence = riskAssessment.Evidence.ToList();

        // Correlate IOCs
        var relationships = _correlationService.Correlate(ioc, results);

        // Generate summary
        var summary = _summaryService.GenerateSummary(riskAssessment, confidenceAssessment, evidence);

        var result = new AnalysisResult(
            ioc,
            riskAssessment,
            confidenceAssessment,
            evidence,
            relationships,
            summary,
            DateTimeOffset.UtcNow);

        return Task.FromResult(result);
    }
}
