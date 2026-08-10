namespace IOCX.Infrastructure.Repositories;

using IOCX.Application;
using Microsoft.EntityFrameworkCore;

/// <summary>Reads and removes investigation history from SQLite.</summary>
public sealed class InvestigationHistoryService : IInvestigationHistoryService
{
    private readonly AppDbContext _context;

    public InvestigationHistoryService(AppDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<InvestigationSummary>> GetHistoryAsync(
        int limit = 0,
        CancellationToken cancellationToken = default)
    {
        // Ordering happens after materialising. The SQLite provider cannot translate
        // ORDER BY on a DateTimeOffset column and throws if asked to.
        var rows = await _context.Investigations
            .AsNoTracking()
            .Include(i => i.Ioc)
            .Include(i => i.Observations)
            .ToListAsync(cancellationToken);

        var ordered = rows
            .OrderByDescending(i => i.StartedAt)
            .Select(i => new InvestigationSummary(
                i.Id,
                i.IocId,
                i.Ioc?.NormalizedValue ?? i.Ioc?.OriginalValue ?? "Unknown",
                i.Ioc?.Type ?? "Unknown",
                i.StartedAt,
                i.CompletedAt,
                i.RiskScore,
                i.RiskLevel ?? "Unrated",
                i.ConfidenceScore,
                i.Observations.Count));

        return limit > 0 ? ordered.Take(limit).ToList() : ordered.ToList();
    }

    /// <inheritdoc />
    public async Task<InvestigationStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
    {
        var levels = await _context.Investigations
            .AsNoTracking()
            .Select(i => i.RiskLevel)
            .ToListAsync(cancellationToken);

        // Counting from the stored band rather than recomputing from the score means a
        // historical row keeps the rating it was given, even if thresholds changed since.
        static bool Is(string? stored, string level) =>
            string.Equals(stored, level, StringComparison.OrdinalIgnoreCase);

        return new InvestigationStatistics(
            levels.Count,
            levels.Count(l => Is(l, "Critical")),
            levels.Count(l => Is(l, "High")),
            levels.Count(l => Is(l, "Medium")),
            levels.Count(l => Is(l, "Low") || Is(l, "Informational")));
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(Guid investigationId, CancellationToken cancellationToken = default)
    {
        var investigation = await _context.Investigations
            .FirstOrDefaultAsync(i => i.Id == investigationId, cancellationToken);

        if (investigation is null)
        {
            return false;
        }

        var iocId = investigation.IocId;

        // Observations and evidence are removed by the cascade configured on their
        // foreign keys, so deleting the investigation is sufficient.
        _context.Investigations.Remove(investigation);
        await _context.SaveChangesAsync(cancellationToken);

        await RemoveIocIfOrphanedAsync(iocId, cancellationToken);

        return true;
    }

    /// <inheritdoc />
    public async Task<int> ClearAllAsync(CancellationToken cancellationToken = default)
    {
        var investigations = await _context.Investigations.ToListAsync(cancellationToken);
        if (investigations.Count == 0)
        {
            return 0;
        }

        _context.Investigations.RemoveRange(investigations);
        await _context.SaveChangesAsync(cancellationToken);

        // Relationships restrict deletion of their endpoints, so they go before the IOCs.
        var relationships = await _context.Relationships.ToListAsync(cancellationToken);
        if (relationships.Count > 0)
        {
            _context.Relationships.RemoveRange(relationships);
            await _context.SaveChangesAsync(cancellationToken);
        }

        var iocs = await _context.Iocs.ToListAsync(cancellationToken);
        if (iocs.Count > 0)
        {
            _context.Iocs.RemoveRange(iocs);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return investigations.Count;
    }

    /// <summary>
    /// Removes an indicator once nothing references it, so clearing history does not leave
    /// behind rows that count toward totals but can never be opened.
    /// </summary>
    private async Task RemoveIocIfOrphanedAsync(Guid iocId, CancellationToken cancellationToken)
    {
        var hasInvestigations = await _context.Investigations
            .AnyAsync(i => i.IocId == iocId, cancellationToken);

        if (hasInvestigations)
        {
            return;
        }

        // Relationship endpoints are restricted rather than cascaded, so an indicator that
        // still appears in the graph is kept.
        var hasRelationships = await _context.Relationships
            .AnyAsync(r => r.SourceIocId == iocId || r.TargetIocId == iocId, cancellationToken);

        if (hasRelationships)
        {
            return;
        }

        var ioc = await _context.Iocs.FirstOrDefaultAsync(i => i.Id == iocId, cancellationToken);
        if (ioc is null)
        {
            return;
        }

        _context.Iocs.Remove(ioc);
        await _context.SaveChangesAsync(cancellationToken);
    }
}
