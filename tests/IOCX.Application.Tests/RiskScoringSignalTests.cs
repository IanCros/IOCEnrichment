namespace IOCX.Application.Tests;

using IOCX.Application.Configuration;
using IOCX.Domain;

/// <summary>
/// Tests each risk signal in isolation, and confirms the engine reaches its verdict from
/// structured findings alone rather than from provider names or display text.
/// </summary>
public class RiskScoringSignalTests
{
    private static readonly Ioc Subject = new("192.0.2.1", "192.0.2.1", IocType.IPv4);

    private static ProviderResult Result(string provider, ProviderFindings findings) =>
        new()
        {
            ProviderName = provider,
            Status = ProviderStatus.Success,
            Timestamp = DateTimeOffset.UtcNow,
            Findings = findings
        };

    [Fact]
    public void NoFindings_ScoresZero()
    {
        var assessment = new RiskScoringService().CalculateRisk(Subject, Array.Empty<ProviderResult>());

        Assert.Equal(0, assessment.Score);
        Assert.Equal(RiskLevel.Informational, assessment.Level);
    }

    [Fact]
    public void FailedProviders_ContributeNothing()
    {
        var results = new List<ProviderResult>
        {
            new() { ProviderName = "VirusTotal", Status = ProviderStatus.Timeout, Timestamp = DateTimeOffset.UtcNow },
            new() { ProviderName = "Shodan", Status = ProviderStatus.RateLimited, Timestamp = DateTimeOffset.UtcNow }
        };

        Assert.Equal(0, new RiskScoringService().CalculateRisk(Subject, results).Score);
    }

    [Fact]
    public void MaliciousDetections_ScaleWithCountAndAreCapped()
    {
        var service = new RiskScoringService();

        var few = service.CalculateRisk(Subject,
            [Result("Engine", new ProviderFindings { Detections = new DetectionFacts(3, 0, 50, 10) })]);

        var many = service.CalculateRisk(Subject,
            [Result("Engine", new ProviderFindings { Detections = new DetectionFacts(80, 0, 5, 0) })]);

        Assert.Equal(6, few.Score);

        // The per-signal cap stops one noisy provider from saturating the score on its own.
        Assert.Equal(new ScoringOptions().MaxDetectionScore, many.Score);
    }

    [Fact]
    public void PositiveReputation_DoesNotAddRisk()
    {
        var findings = new ProviderFindings { Detections = new DetectionFacts(0, 0, 90, 5, Reputation: 40) };

        Assert.Equal(0, new RiskScoringService().CalculateRisk(Subject, [Result("Engine", findings)]).Score);
    }

    [Fact]
    public void NegativeReputation_AddsRisk()
    {
        var findings = new ProviderFindings { Detections = new DetectionFacts(0, 0, 90, 5, Reputation: -80) };

        Assert.Equal(8, new RiskScoringService().CalculateRisk(Subject, [Result("Engine", findings)]).Score);
    }

    [Theory]
    [InlineData(10, 0)]
    [InlineData(49, 0)]
    [InlineData(50, 10)]
    [InlineData(74, 10)]
    [InlineData(75, 20)]
    [InlineData(100, 20)]
    public void AbuseConfidence_CrossesConfiguredBands(int confidence, int expected)
    {
        var findings = new ProviderFindings { Abuse = new AbuseFacts(confidence) };

        Assert.Equal(expected, new RiskScoringService().CalculateRisk(Subject, [Result("Abuse", findings)]).Score);
    }

    [Fact]
    public void MalwareAssociation_IsScoredOncePerInvestigation()
    {
        var service = new RiskScoringService();

        // Two providers naming families must not stack the weight twice. Agreement is
        // what the corroboration signal is for.
        var results = new List<ProviderResult>
        {
            Result("FeedA", new ProviderFindings { ThreatMatches = new ThreatMatchFacts(1, ["ExampleMalware"]) }),
            Result("FeedB", new ProviderFindings { ThreatMatches = new ThreatMatchFacts(1, ["ExampleMalware"]) })
        };

        var assessment = service.CalculateRisk(Subject, results);

        Assert.Single(assessment.Evidence, e => e.Category == EvidenceCategory.MalwareAssociation);
    }

    [Fact]
    public void Corroboration_RequiresTwoIndependentProviders()
    {
        var service = new RiskScoringService();

        var single = service.CalculateRisk(Subject,
            [Result("FeedA", new ProviderFindings { Detections = new DetectionFacts(5, 0, 0, 0) })]);

        var paired = service.CalculateRisk(Subject,
        [
            Result("FeedA", new ProviderFindings { Detections = new DetectionFacts(5, 0, 0, 0) }),
            Result("FeedB", new ProviderFindings { Abuse = new AbuseFacts(90) })
        ]);

        Assert.DoesNotContain(single.Evidence, e => e.Category == EvidenceCategory.ProviderAgreement);
        Assert.Contains(paired.Evidence, e => e.Category == EvidenceCategory.ProviderAgreement);
    }

    [Fact]
    public void Recency_AddsRiskOnlyForActivityInsideTheWindow()
    {
        var service = new RiskScoringService();

        var recent = service.CalculateRisk(Subject,
        [
            Result("Feed", new ProviderFindings
            {
                ThreatMatches = new ThreatMatchFacts(1),
                LastActivityAt = DateTimeOffset.UtcNow.AddDays(-2)
            })
        ]);

        var stale = service.CalculateRisk(Subject,
        [
            Result("Feed", new ProviderFindings
            {
                ThreatMatches = new ThreatMatchFacts(1),
                LastActivityAt = DateTimeOffset.UtcNow.AddYears(-3)
            })
        ]);

        Assert.Contains(recent.Evidence, e => e.Category == EvidenceCategory.Recency);
        Assert.DoesNotContain(stale.Evidence, e => e.Category == EvidenceCategory.Recency);
        Assert.True(recent.Score > stale.Score);
    }

    [Fact]
    public void Score_IsClampedToOneHundred()
    {
        var results = new List<ProviderResult>
        {
            Result("A", new ProviderFindings { Detections = new DetectionFacts(500, 0, 0, 0, -900) }),
            Result("B", new ProviderFindings { Abuse = new AbuseFacts(100) }),
            Result("C", new ProviderFindings
            {
                ThreatMatches = new ThreatMatchFacts(50, ["Family1", "Family2"]),
                LastActivityAt = DateTimeOffset.UtcNow
            })
        };

        var assessment = new RiskScoringService().CalculateRisk(Subject, results);

        Assert.Equal(100, assessment.Score);
        Assert.Equal(RiskLevel.Critical, assessment.Level);
    }

    [Fact]
    public void Thresholds_AreConfigurable()
    {
        // A deployment that wants an aggressive posture can lower the bands without a recompile.
        var strict = new RiskScoringService(new ScoringOptions
        {
            LowThreshold = 1,
            MediumThreshold = 5,
            HighThreshold = 10,
            CriticalThreshold = 15
        });

        var findings = new ProviderFindings { Detections = new DetectionFacts(8, 0, 0, 0) };

        var assessment = strict.CalculateRisk(Subject, [Result("Engine", findings)]);

        Assert.Equal(16, assessment.Score);
        Assert.Equal(RiskLevel.Critical, assessment.Level);
    }

    [Fact]
    public void Evidence_AttributesEachSignalToItsProvider()
    {
        var results = new List<ProviderResult>
        {
            Result("ScannerX", new ProviderFindings { Detections = new DetectionFacts(4, 0, 60, 10) }),
            Result("AbuseFeedY", new ProviderFindings { Abuse = new AbuseFacts(90, 12) })
        };

        var assessment = new RiskScoringService().CalculateRisk(Subject, results);

        Assert.Contains(assessment.Evidence, e => e.Provider == "ScannerX");
        Assert.Contains(assessment.Evidence, e => e.Provider == "AbuseFeedY");

        // The engine describes findings using the reporting provider's own name, proving it
        // never needed a hardcoded list of known providers.
        Assert.Contains(assessment.Evidence, e => e.Description.Contains("ScannerX", StringComparison.Ordinal));
    }

    [Fact]
    public void EvidenceContributions_SumToTheScore()
    {
        var results = new List<ProviderResult>
        {
            Result("A", new ProviderFindings { Detections = new DetectionFacts(4, 0, 60, 10, -30) }),
            Result("B", new ProviderFindings { Abuse = new AbuseFacts(80) })
        };

        var assessment = new RiskScoringService().CalculateRisk(Subject, results);

        // Every point in the score must be explained by a listed piece of evidence.
        Assert.Equal(assessment.Score, assessment.Evidence.Sum(e => e.ScoreContribution));
    }
}
