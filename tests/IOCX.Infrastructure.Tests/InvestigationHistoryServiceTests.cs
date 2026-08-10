namespace IOCX.Infrastructure.Tests;

using IOCX.Domain.Entities;
using IOCX.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Covers reading and deleting stored investigation history against real SQLite,
/// including that deletes cascade to child rows rather than orphaning them.
/// </summary>
public class InvestigationHistoryServiceTests : IDisposable
{
    private readonly SqliteTestContext _fixture = new();
    private readonly InvestigationHistoryService _service;

    public InvestigationHistoryServiceTests()
    {
        _service = new InvestigationHistoryService(_fixture.Context);
    }

    public void Dispose() => _fixture.Dispose();

    private async Task<(Guid IocId, Guid InvestigationId)> SeedAsync(
        string value = "192.0.2.1",
        string riskLevel = "Critical",
        int observations = 2)
    {
        var ioc = new IocEntity
        {
            Id = Guid.NewGuid(),
            OriginalValue = value,
            NormalizedValue = value,
            Type = "IPv4",
            CreatedAt = DateTimeOffset.UtcNow
        };

        var investigation = new InvestigationEntity
        {
            Id = Guid.NewGuid(),
            IocId = ioc.Id,
            StartedAt = DateTimeOffset.UtcNow,
            CompletedAt = DateTimeOffset.UtcNow,
            RiskScore = 81,
            RiskLevel = riskLevel,
            ConfidenceScore = 81
        };

        _fixture.Context.Iocs.Add(ioc);
        _fixture.Context.Investigations.Add(investigation);

        for (var i = 0; i < observations; i++)
        {
            _fixture.Context.Observations.Add(new ProviderObservationEntity
            {
                Id = Guid.NewGuid(),
                InvestigationId = investigation.Id,
                ProviderName = $"Provider{i}",
                Status = "Success",
                RetrievedAt = DateTimeOffset.UtcNow
            });
        }

        _fixture.Context.Evidence.Add(new EvidenceEntity
        {
            Id = Guid.NewGuid(),
            InvestigationId = investigation.Id,
            Category = "Reputation",
            Description = "Test evidence",
            Severity = "High",
            ScoreContribution = 25,
            Provider = "Provider0",
            ObservedAt = DateTimeOffset.UtcNow
        });

        await _fixture.Context.SaveChangesAsync();
        return (ioc.Id, investigation.Id);
    }

    [Fact]
    public async Task GetHistoryAsync_ReturnsStoredInvestigations()
    {
        await SeedAsync();

        var history = await _service.GetHistoryAsync();

        var row = Assert.Single(history);
        Assert.Equal("192.0.2.1", row.Value);
        Assert.Equal("Critical", row.RiskLevel);
        Assert.Equal(2, row.ObservationCount);
    }

    [Fact]
    public async Task GetHistoryAsync_RespectsLimit()
    {
        await SeedAsync("192.0.2.1");
        await SeedAsync("192.0.2.2");
        await SeedAsync("192.0.2.3");

        Assert.Equal(2, (await _service.GetHistoryAsync(limit: 2)).Count);
        Assert.Equal(3, (await _service.GetHistoryAsync()).Count);
    }

    [Fact]
    public async Task GetStatisticsAsync_CountsByBand()
    {
        await SeedAsync("192.0.2.1", "Critical");
        await SeedAsync("192.0.2.2", "High");
        await SeedAsync("192.0.2.3", "Informational");
        await SeedAsync("192.0.2.4", "Low");

        var stats = await _service.GetStatisticsAsync();

        Assert.Equal(4, stats.Total);
        Assert.Equal(1, stats.Critical);
        Assert.Equal(1, stats.High);
        Assert.Equal(0, stats.Medium);

        // Low and Informational share a tile on the dashboard.
        Assert.Equal(2, stats.LowOrInformational);
    }

    [Fact]
    public async Task DeleteAsync_RemovesInvestigation()
    {
        var (_, investigationId) = await SeedAsync();

        Assert.True(await _service.DeleteAsync(investigationId));
        Assert.Equal(0, await _fixture.Context.Investigations.CountAsync());
    }

    [Fact]
    public async Task DeleteAsync_CascadesToObservationsAndEvidence()
    {
        var (_, investigationId) = await SeedAsync();

        await _service.DeleteAsync(investigationId);

        // Leaving these behind would inflate storage and corrupt any later reporting.
        Assert.Equal(0, await _fixture.Context.Observations.CountAsync());
        Assert.Equal(0, await _fixture.Context.Evidence.CountAsync());
    }

    [Fact]
    public async Task DeleteAsync_RemovesIndicatorOnceNothingReferencesIt()
    {
        var (_, investigationId) = await SeedAsync();

        await _service.DeleteAsync(investigationId);

        // An indicator with no investigations can never be opened, so it should not linger.
        Assert.Equal(0, await _fixture.Context.Iocs.CountAsync());
    }

    [Fact]
    public async Task DeleteAsync_KeepsIndicatorWhileOtherInvestigationsRemain()
    {
        var ioc = new IocEntity
        {
            Id = Guid.NewGuid(),
            OriginalValue = "192.0.2.1",
            NormalizedValue = "192.0.2.1",
            Type = "IPv4",
            CreatedAt = DateTimeOffset.UtcNow
        };

        _fixture.Context.Iocs.Add(ioc);

        var first = new InvestigationEntity { Id = Guid.NewGuid(), IocId = ioc.Id, StartedAt = DateTimeOffset.UtcNow, RiskLevel = "Low" };
        var second = new InvestigationEntity { Id = Guid.NewGuid(), IocId = ioc.Id, StartedAt = DateTimeOffset.UtcNow, RiskLevel = "High" };

        _fixture.Context.Investigations.AddRange(first, second);
        await _fixture.Context.SaveChangesAsync();

        await _service.DeleteAsync(first.Id);

        // Deleting one point in an indicator's history must not destroy the rest of it.
        Assert.Equal(1, await _fixture.Context.Iocs.CountAsync());
        Assert.Equal(1, await _fixture.Context.Investigations.CountAsync());
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalseForUnknownInvestigation()
    {
        await SeedAsync();

        Assert.False(await _service.DeleteAsync(Guid.NewGuid()));
        Assert.Equal(1, await _fixture.Context.Investigations.CountAsync());
    }

    [Fact]
    public async Task ClearAllAsync_RemovesEverything()
    {
        await SeedAsync("192.0.2.1");
        await SeedAsync("192.0.2.2");

        var deleted = await _service.ClearAllAsync();

        Assert.Equal(2, deleted);
        Assert.Equal(0, await _fixture.Context.Investigations.CountAsync());
        Assert.Equal(0, await _fixture.Context.Observations.CountAsync());
        Assert.Equal(0, await _fixture.Context.Evidence.CountAsync());
        Assert.Equal(0, await _fixture.Context.Iocs.CountAsync());
    }

    [Fact]
    public async Task ClearAllAsync_OnEmptyDatabaseIsHarmless()
    {
        Assert.Equal(0, await _service.ClearAllAsync());
    }

    [Fact]
    public async Task Deletions_AreVisibleToASeparateContext()
    {
        var (_, investigationId) = await SeedAsync();

        await _service.DeleteAsync(investigationId);

        // Proves the delete was committed rather than only removed from the tracker.
        using var other = _fixture.CreateSeparateContext();
        Assert.Equal(0, await other.Investigations.CountAsync());
    }
}
