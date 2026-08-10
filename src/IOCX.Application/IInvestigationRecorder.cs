namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Persists a completed investigation so it appears in history and dashboard figures.</summary>
/// <remarks>
/// Implemented in the infrastructure layer. Declared here so the orchestration service can
/// record its work without taking a dependency on Entity Framework.
/// </remarks>
public interface IInvestigationRecorder
{
    /// <summary>
    /// Stores an investigation together with its provider observations, evidence, and
    /// discovered relationships.
    /// </summary>
    Task<Guid> RecordAsync(
        Ioc ioc,
        IReadOnlyCollection<ProviderResult> results,
        AnalysisResult analysis,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken = default);
}

/// <summary>Runs an end-to-end investigation. Enrich, analyse, and persist.</summary>
public interface IInvestigationService
{
    /// <summary>Investigates an indicator and stores the outcome.</summary>
    Task<InvestigationOutcome> InvestigateAsync(
        Ioc ioc,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);
}

/// <summary>The result of a completed investigation.</summary>
public sealed record InvestigationOutcome(
    Guid? InvestigationId,
    Ioc Ioc,
    IReadOnlyList<ProviderResult> Results,
    AnalysisResult Analysis,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt);

/// <summary>
/// Default orchestration. Enrich across providers, analyse the results, then record them.
/// </summary>
/// <remarks>
/// This exists so the workflow lives in the application layer rather than in a view model.
/// The CLI, bulk analysis, and the desktop UI can all drive the same pipeline.
/// </remarks>
public sealed class InvestigationService : IInvestigationService
{
    private readonly IEnrichmentService _enrichmentService;
    private readonly IInvestigationAnalysisService _analysisService;
    private readonly IInvestigationRecorder? _recorder;

    public InvestigationService(
        IEnrichmentService enrichmentService,
        IInvestigationAnalysisService analysisService,
        IInvestigationRecorder? recorder = null)
    {
        _enrichmentService = enrichmentService ?? throw new ArgumentNullException(nameof(enrichmentService));
        _analysisService = analysisService ?? throw new ArgumentNullException(nameof(analysisService));
        _recorder = recorder;
    }

    /// <inheritdoc />
    public async Task<InvestigationOutcome> InvestigateAsync(
        Ioc ioc,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ioc);

        var startedAt = DateTimeOffset.UtcNow;

        progress?.Report("Querying intelligence providers...");
        var results = await _enrichmentService.EnrichAsync(ioc, cancellationToken);

        progress?.Report("Scoring and correlating results...");
        var analysis = await _analysisService.AnalyzeAsync(ioc, results, cancellationToken);

        Guid? investigationId = null;
        if (_recorder is not null)
        {
            progress?.Report("Saving investigation...");

            // Persistence deliberately runs without the caller's token. Once enrichment has
            // completed, discarding the result because the user pressed Cancel would lose
            // work that has already been paid for in provider quota.
            investigationId = await _recorder.RecordAsync(
                ioc, results, analysis, startedAt, CancellationToken.None);
        }

        return new InvestigationOutcome(
            investigationId, ioc, results, analysis, startedAt, DateTimeOffset.UtcNow);
    }
}
