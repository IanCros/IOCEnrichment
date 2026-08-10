namespace IOCX.Infrastructure.Repositories;

using IOCX.Application;
using IOCX.Domain;
using IOCX.Domain.Entities;
using Microsoft.EntityFrameworkCore;

/// <summary>Persists investigations to SQLite through Entity Framework Core.</summary>
/// <remarks>
/// Indicators are stored once and reused across investigations, keyed by normalized value, so
/// repeat analysis of the same indicator builds a history against a single row rather than
/// creating duplicates.
/// </remarks>
public sealed class InvestigationRecorder : IInvestigationRecorder
{
    private readonly AppDbContext _context;

    public InvestigationRecorder(AppDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<Guid> RecordAsync(
        Ioc ioc,
        IReadOnlyCollection<ProviderResult> results,
        AnalysisResult analysis,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ioc);
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(analysis);

        var completedAt = DateTimeOffset.UtcNow;
        var iocEntity = await GetOrCreateIocAsync(ioc, completedAt, cancellationToken);

        var investigation = new InvestigationEntity
        {
            Id = Guid.NewGuid(),
            IocId = iocEntity.Id,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            RiskScore = analysis.RiskAssessment.Score,
            RiskLevel = analysis.RiskAssessment.Level.ToString(),
            ConfidenceScore = analysis.ConfidenceAssessment.Score
        };

        _context.Investigations.Add(investigation);

        // Failures are recorded alongside successes. Knowing that a provider timed out is part
        // of interpreting the confidence score later.
        foreach (var result in results)
        {
            _context.Observations.Add(new ProviderObservationEntity
            {
                Id = Guid.NewGuid(),
                InvestigationId = investigation.Id,
                ProviderName = result.ProviderName,
                Status = result.Status.ToString(),
                RetrievedAt = result.Timestamp,
                Duration = result.Duration,
                NormalizedResult = result.NormalizedData ?? result.ErrorMessage
            });
        }

        foreach (var evidence in analysis.Evidence)
        {
            _context.Evidence.Add(new EvidenceEntity
            {
                Id = Guid.NewGuid(),
                InvestigationId = investigation.Id,
                Category = evidence.Category.ToString(),
                Description = evidence.Description,
                Severity = evidence.Severity.ToString(),
                ScoreContribution = evidence.ScoreContribution,
                Provider = evidence.Provider,
                ObservedAt = evidence.Timestamp
            });
        }

        await PersistRelationshipsAsync(iocEntity, analysis, completedAt, cancellationToken);

        iocEntity.LastInvestigatedAt = completedAt;

        await _context.SaveChangesAsync(cancellationToken);

        return investigation.Id;
    }

    private async Task<IocEntity> GetOrCreateIocAsync(
        Ioc ioc,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var existing = await _context.Iocs
            .FirstOrDefaultAsync(i => i.NormalizedValue == ioc.NormalizedValue, cancellationToken);

        if (existing is not null)
        {
            return existing;
        }

        var entity = new IocEntity
        {
            Id = ioc.Id,
            OriginalValue = ioc.OriginalValue,
            NormalizedValue = ioc.NormalizedValue,
            Type = ioc.Type.ToString(),
            CreatedAt = now
        };

        _context.Iocs.Add(entity);
        return entity;
    }

    private async Task PersistRelationshipsAsync(
        IocEntity source,
        AnalysisResult analysis,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        foreach (var relationship in analysis.Relationships)
        {
            // The correlation engine reports relationship targets by identifier. Only store
            // edges whose target indicator actually exists, so the graph never contains
            // dangling references.
            var targetExists = await _context.Iocs
                .AnyAsync(i => i.Id == relationship.TargetIocId, cancellationToken);

            if (!targetExists || relationship.TargetIocId == source.Id)
            {
                continue;
            }

            var alreadyStored = await _context.Relationships.AnyAsync(
                r => r.SourceIocId == source.Id
                     && r.TargetIocId == relationship.TargetIocId
                     && r.RelationshipType == relationship.Type.ToString(),
                cancellationToken);

            if (alreadyStored)
            {
                continue;
            }

            _context.Relationships.Add(new RelationshipEntity
            {
                Id = Guid.NewGuid(),
                SourceIocId = source.Id,
                TargetIocId = relationship.TargetIocId,
                RelationshipType = relationship.Type.ToString(),
                Confidence = relationship.Confidence,
                CreatedAt = now
            });
        }
    }
}
