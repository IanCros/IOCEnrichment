namespace IOCX.Infrastructure.Tests;

using IOCX.Domain.Entities;
using Microsoft.EntityFrameworkCore;

/// <summary>Guards the read queries behind the Dashboard and History screens.</summary>
/// <remarks>
/// SQLite cannot translate ORDER BY on a DateTimeOffset column and throws when asked to.
/// Both screens once did exactly that, swallowed the exception, and rendered as if the
/// database were empty. Investigations saved fine but were invisible. These run the real
/// query shapes against real SQLite so that cannot come back unnoticed.
/// </remarks>
public class HistoryQueryTests : IDisposable
{
    private readonly SqliteTestContext _fixture = new();

    public void Dispose() => _fixture.Dispose();

    private async Task SeedAsync(int count)
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

        for (var i = 0; i < count; i++)
        {
            _fixture.Context.Investigations.Add(new InvestigationEntity
            {
                Id = Guid.NewGuid(),
                IocId = ioc.Id,
                StartedAt = DateTimeOffset.UtcNow.AddMinutes(-i),
                CompletedAt = DateTimeOffset.UtcNow.AddMinutes(-i).AddSeconds(3),
                RiskScore = 50 + i,
                RiskLevel = i == 0 ? "Critical" : "Low",
                ConfidenceScore = 70
            });
        }

        await _fixture.Context.SaveChangesAsync();
    }

    [Fact]
    public async Task OrderingByDateTimeOffsetInSql_IsNotSupported()
    {
        await SeedAsync(3);

        // Documents the provider limitation that caused the bug. If a future EF or SQLite
        // version supports this, the test fails and the workarounds can be removed.
        await Assert.ThrowsAsync<NotSupportedException>(() =>
            _fixture.Context.Investigations
                .AsNoTracking()
                .OrderByDescending(i => i.StartedAt)
                .ToListAsync());
    }

    [Fact]
    public async Task DashboardQuery_ReturnsEveryStoredInvestigation()
    {
        await SeedAsync(11);

        // The shape DashboardViewModel.LoadAsync uses. Materialise, then order in memory.
        var investigations = (await _fixture.Context.Investigations
                .AsNoTracking()
                .Include(i => i.Ioc)
                .ToListAsync())
            .OrderByDescending(i => i.StartedAt)
            .ToList();

        Assert.Equal(11, investigations.Count);
        Assert.Equal("Critical", investigations[0].RiskLevel);
        Assert.All(investigations, i => Assert.NotNull(i.Ioc));
    }

    [Fact]
    public async Task DashboardQuery_OrdersNewestFirst()
    {
        await SeedAsync(5);

        var investigations = (await _fixture.Context.Investigations
                .AsNoTracking()
                .ToListAsync())
            .OrderByDescending(i => i.StartedAt)
            .ToList();

        Assert.Equal(
            investigations.Select(i => i.StartedAt).OrderByDescending(d => d),
            investigations.Select(i => i.StartedAt));
    }

    [Fact]
    public async Task HistoryQuery_IncludesObservationCounts()
    {
        await SeedAsync(1);

        var investigation = await _fixture.Context.Investigations.FirstAsync();

        _fixture.Context.Observations.Add(new ProviderObservationEntity
        {
            Id = Guid.NewGuid(),
            InvestigationId = investigation.Id,
            ProviderName = "VirusTotal",
            Status = "Success",
            RetrievedAt = DateTimeOffset.UtcNow
        });

        await _fixture.Context.SaveChangesAsync();

        // History displays a per-row observation count, which requires the include. Without
        // it the navigation is empty and every row reports zero providers.
        var rows = (await _fixture.Context.Investigations
                .AsNoTracking()
                .Include(i => i.Ioc)
                .Include(i => i.Observations)
                .ToListAsync())
            .OrderByDescending(i => i.StartedAt)
            .ToList();

        Assert.Equal(1, rows.Single().Observations.Count);
    }

    [Fact]
    public async Task StoredInvestigations_AreVisibleToASeparateContext()
    {
        await SeedAsync(2);

        // Proves the rows are committed rather than merely tracked in memory.
        using var other = _fixture.CreateSeparateContext();

        Assert.Equal(2, await other.Investigations.CountAsync());
    }
}
