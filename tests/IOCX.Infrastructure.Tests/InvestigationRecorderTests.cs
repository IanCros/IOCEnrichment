namespace IOCX.Infrastructure.Tests;

using IOCX.Application;
using IOCX.Domain;
using IOCX.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Tests that a completed investigation is persisted in full, so history and dashboard
/// figures reflect work that was actually done.
/// </summary>
public class InvestigationRecorderTests : IDisposable
{
    private readonly SqliteTestContext _fixture = new();
    private readonly AppDbContext _context;

    public InvestigationRecorderTests()
    {
        // Real SQLite, not the EF in-memory provider. See SqliteTestContext for why.
        _context = _fixture.Context;
    }

    public void Dispose() => _fixture.Dispose();

    private static Ioc CreateIoc(string value = "192.0.2.1", IocType type = IocType.IPv4) =>
        new(value, value, type);

    private static AnalysisResult CreateAnalysis(Ioc ioc, int score = 72)
    {
        var evidence = new List<Evidence>
        {
            new(EvidenceCategory.Reputation, "12 of 90 engines flagged the indicator.",
                EvidenceSeverity.High, 24, "VirusTotal", DateTimeOffset.UtcNow)
        };

        return new AnalysisResult(
            ioc,
            new RiskAssessment(ioc, score, RiskLevel.High, evidence, DateTimeOffset.UtcNow),
            new ConfidenceAssessment(88, "Two independent providers agreed."),
            evidence,
            Array.Empty<IocRelationship>(),
            "Assessed as HIGH risk with 88% confidence.",
            DateTimeOffset.UtcNow);
    }

    private static List<ProviderResult> CreateResults() =>
    [
        new ProviderResult
        {
            ProviderName = "VirusTotal",
            Status = ProviderStatus.Success,
            Timestamp = DateTimeOffset.UtcNow,
            Duration = 240,
            NormalizedData = "Malicious: 12"
        },
        new ProviderResult
        {
            ProviderName = "Shodan",
            Status = ProviderStatus.RateLimited,
            Timestamp = DateTimeOffset.UtcNow,
            ErrorMessage = "Rate limit exceeded."
        }
    ];

    [Fact]
    public async Task RecordAsync_StoresInvestigationWithScores()
    {
        var recorder = new InvestigationRecorder(_context);
        var ioc = CreateIoc();
        var startedAt = DateTimeOffset.UtcNow.AddSeconds(-3);

        var id = await recorder.RecordAsync(ioc, CreateResults(), CreateAnalysis(ioc), startedAt);

        var stored = await _context.Investigations.SingleAsync(i => i.Id == id);
        Assert.Equal(72, stored.RiskScore);
        Assert.Equal("High", stored.RiskLevel);
        Assert.Equal(88, stored.ConfidenceScore);
        Assert.NotNull(stored.CompletedAt);
    }

    [Fact]
    public async Task RecordAsync_StoresFailedProvidersAlongsideSuccesses()
    {
        var recorder = new InvestigationRecorder(_context);
        var ioc = CreateIoc();

        var id = await recorder.RecordAsync(ioc, CreateResults(), CreateAnalysis(ioc), DateTimeOffset.UtcNow);

        var observations = await _context.Observations
            .Where(o => o.InvestigationId == id)
            .ToListAsync();

        Assert.Equal(2, observations.Count);

        // Knowing a provider was rate limited is part of interpreting the confidence score.
        var rateLimited = observations.Single(o => o.ProviderName == "Shodan");
        Assert.Equal("RateLimited", rateLimited.Status);
        Assert.Equal("Rate limit exceeded.", rateLimited.NormalizedResult);
    }

    [Fact]
    public async Task RecordAsync_StoresEvidence()
    {
        var recorder = new InvestigationRecorder(_context);
        var ioc = CreateIoc();

        var id = await recorder.RecordAsync(ioc, CreateResults(), CreateAnalysis(ioc), DateTimeOffset.UtcNow);

        var evidence = await _context.Evidence.Where(e => e.InvestigationId == id).ToListAsync();

        var item = Assert.Single(evidence);
        Assert.Equal("Reputation", item.Category);
        Assert.Equal(24, item.ScoreContribution);
    }

    [Fact]
    public async Task RecordAsync_ReusesIocAcrossInvestigations()
    {
        var recorder = new InvestigationRecorder(_context);
        var ioc = CreateIoc();

        await recorder.RecordAsync(ioc, CreateResults(), CreateAnalysis(ioc, 40), DateTimeOffset.UtcNow);

        // A second run of the same indicator must build history against one IOC row,
        // which is what makes risk-over-time comparison possible.
        var second = CreateIoc();
        await recorder.RecordAsync(second, CreateResults(), CreateAnalysis(second, 91), DateTimeOffset.UtcNow);

        Assert.Equal(1, await _context.Iocs.CountAsync());
        Assert.Equal(2, await _context.Investigations.CountAsync());

        var stored = await _context.Iocs.SingleAsync();
        Assert.Equal(2, await _context.Investigations.CountAsync(i => i.IocId == stored.Id));
    }

    [Fact]
    public async Task RecordAsync_UpdatesLastInvestigatedTimestamp()
    {
        var recorder = new InvestigationRecorder(_context);
        var ioc = CreateIoc();

        await recorder.RecordAsync(ioc, CreateResults(), CreateAnalysis(ioc), DateTimeOffset.UtcNow);

        var stored = await _context.Iocs.SingleAsync();
        Assert.NotNull(stored.LastInvestigatedAt);
    }

    [Fact]
    public async Task RecordAsync_SkipsRelationshipsWithUnknownTargets()
    {
        var recorder = new InvestigationRecorder(_context);
        var ioc = CreateIoc();

        var analysis = CreateAnalysis(ioc) with
        {
            Relationships = new List<IocRelationship>
            {
                new(ioc.Id, Guid.NewGuid(), RelationshipType.ResolvesTo, 80, "DNS", DateTimeOffset.UtcNow)
            }
        };

        await recorder.RecordAsync(ioc, CreateResults(), analysis, DateTimeOffset.UtcNow);

        // A dangling edge would break graph traversal, so unknown targets are dropped.
        Assert.Equal(0, await _context.Relationships.CountAsync());
    }
}
