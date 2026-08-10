namespace IOCX.Application;

/// <summary>A stored investigation, flattened for display.</summary>
public sealed record InvestigationSummary(
    Guid Id,
    Guid IocId,
    string Value,
    string Type,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt,
    int? RiskScore,
    string RiskLevel,
    int? ConfidenceScore,
    int ObservationCount);

/// <summary>Counts by risk band, for the dashboard tiles.</summary>
public sealed record InvestigationStatistics(
    int Total,
    int Critical,
    int High,
    int Medium,
    int LowOrInformational);

/// <summary>
/// Reads and removes stored history. Lets view models show and manage investigations
/// without holding a DbContext or touching entity types.
/// </summary>
public interface IInvestigationHistoryService
{
    /// <summary>Newest first. A limit of zero returns everything.</summary>
    Task<IReadOnlyList<InvestigationSummary>> GetHistoryAsync(
        int limit = 0,
        CancellationToken cancellationToken = default);

    Task<InvestigationStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default);

    /// <summary>Also deletes the observations and evidence. False if the row had already gone.</summary>
    Task<bool> DeleteAsync(Guid investigationId, CancellationToken cancellationToken = default);

    /// <summary>Returns how many were deleted.</summary>
    Task<int> ClearAllAsync(CancellationToken cancellationToken = default);
}
