namespace IOCX.Application.Tests;

using IOCX.Application;
using IOCX.Domain;

/// <summary>
/// Tests for risk scoring, confidence scoring, correlation, summary, and analysis orchestration.
/// </summary>
public class AnalysisEngineTests
{
    private static Ioc CreateIoc(string value, IocType type) => new(value, value, type);
    private static IRateLimiter CreateNoOpRateLimiter() => new NoOpRateLimiter();

    [Fact]
    public void RiskScoring_CleanIoc_ReturnsInformational()
    {
        var service = new RiskScoringService();
        var ioc = CreateIoc("example.com", IocType.Domain);
        var results = new List<ProviderResult>();

        var assessment = service.CalculateRisk(ioc, results);

        Assert.Equal(0, assessment.Score);
        Assert.Equal(RiskLevel.Informational, assessment.Level);
        Assert.Empty(assessment.Evidence);
    }

    [Fact]
    public void RiskScoring_MaliciousIoc_ReturnsHighOrCritical()
    {
        var service = new RiskScoringService();
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "VirusTotal", Status = ProviderStatus.Success, NormalizedData = "Malicious: 15" + Environment.NewLine + "Suspicious: 3" + Environment.NewLine + "Harmless: 65" + Environment.NewLine + "Undetected: 20" + Environment.NewLine + "Reputation: -50", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "AbuseIPDB", Status = ProviderStatus.Success, NormalizedData = "Abuse Confidence: 85%" + Environment.NewLine + "Country: US", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "ThreatFox", Status = ProviderStatus.Success, NormalizedData = "Matches: 2" + Environment.NewLine + "Malware: ExampleMalware", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "URLhaus", Status = ProviderStatus.Success, NormalizedData = "Matches: 1" + Environment.NewLine + "Malware: Trojan", Timestamp = DateTimeOffset.UtcNow }
        };

        var assessment = service.CalculateRisk(ioc, results);

        Assert.True(assessment.Score >= 60, $"Expected score >= 60, got {assessment.Score}");
        Assert.True(assessment.Level is RiskLevel.High or RiskLevel.Critical);
        Assert.NotEmpty(assessment.Evidence);
    }

    [Fact]
    public void RiskScoring_ConflictingEvidence_DoesNotBlindlyMaximize()
    {
        var service = new RiskScoringService();
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "VirusTotal", Status = ProviderStatus.Success, NormalizedData = "Malicious: 1" + Environment.NewLine + "Suspicious: 0" + Environment.NewLine + "Harmless: 100" + Environment.NewLine + "Reputation: 10", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "AbuseIPDB", Status = ProviderStatus.Success, NormalizedData = "Abuse Confidence: 0%" + Environment.NewLine + "Country: US", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "ThreatFox", Status = ProviderStatus.Success, NormalizedData = "Matches: 0", Timestamp = DateTimeOffset.UtcNow }
        };

        var assessment = service.CalculateRisk(ioc, results);

        Assert.True(assessment.Score < 60, $"Expected score < 60 due to benign signals, got {assessment.Score}");
    }

    [Fact]
    public void RiskScoring_ProviderFailure_StillCalculatesScore()
    {
        var service = new RiskScoringService();
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "VirusTotal", Status = ProviderStatus.Success, NormalizedData = "Malicious: 10", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "AbuseIPDB", Status = ProviderStatus.Timeout, ErrorMessage = "Request timed out.", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "ThreatFox", Status = ProviderStatus.Success, NormalizedData = "Matches: 1", Timestamp = DateTimeOffset.UtcNow }
        };

        var assessment = service.CalculateRisk(ioc, results);

        Assert.True(assessment.Score > 0);
        Assert.NotEmpty(assessment.Evidence);
    }

    [Fact]
    public void ConfidenceScoring_AllProvidersSucceed_ReturnsHighConfidence()
    {
        var riskService = new RiskScoringService();
        var confidenceService = new ConfidenceScoringService();
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "VirusTotal", Status = ProviderStatus.Success, NormalizedData = "Malicious: 10", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "AbuseIPDB", Status = ProviderStatus.Success, NormalizedData = "Abuse Confidence: 85%", Timestamp = DateTimeOffset.UtcNow }
        };

        var riskAssessment = riskService.CalculateRisk(ioc, results);
        var confidence = confidenceService.CalculateConfidence(ioc, results, riskAssessment);

        Assert.True(confidence.Score >= 50);
        Assert.False(string.IsNullOrWhiteSpace(confidence.Reason));
    }

    [Fact]
    public void ConfidenceScoring_ProviderFailure_ReducesConfidence()
    {
        var riskService = new RiskScoringService();
        var confidenceService = new ConfidenceScoringService();
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "VirusTotal", Status = ProviderStatus.Success, NormalizedData = "Malicious: 10", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "AbuseIPDB", Status = ProviderStatus.Timeout, Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "ThreatFox", Status = ProviderStatus.Unauthorized, Timestamp = DateTimeOffset.UtcNow }
        };

        var riskAssessment = riskService.CalculateRisk(ioc, results);
        var confidence = confidenceService.CalculateConfidence(ioc, results, riskAssessment);

        Assert.True(confidence.Score < 70);
    }

    [Fact]
    public void Correlation_DomainWithARecord_ReturnsResolveRelationship()
    {
        var correlationService = new IocCorrelationService();
        var ioc = CreateIoc("example.com", IocType.Domain);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "DNS", Status = ProviderStatus.Success, NormalizedData = "A:" + Environment.NewLine + "93.184.216.34", Timestamp = DateTimeOffset.UtcNow }
        };

        var relationships = correlationService.Correlate(ioc, results);

        Assert.NotEmpty(relationships);
        Assert.Contains(relationships, r => r.Type == RelationshipType.ResolvesTo);
    }

    [Fact]
    public void Correlation_MalwareAssociation_ReturnsMalwareRelationship()
    {
        var correlationService = new IocCorrelationService();
        var ioc = CreateIoc("example.com", IocType.Domain);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "ThreatFox", Status = ProviderStatus.Success, NormalizedData = "Matches: 1" + Environment.NewLine + "Malware: ExampleMalware", Timestamp = DateTimeOffset.UtcNow }
        };

        var relationships = correlationService.Correlate(ioc, results);

        Assert.NotEmpty(relationships);
        Assert.Contains(relationships, r => r.Type == RelationshipType.AssociatedWithMalware);
    }

    [Fact]
    public void Correlation_DuplicateRelationships_AreDeduplicated()
    {
        var correlationService = new IocCorrelationService();
        var ioc = CreateIoc("example.com", IocType.Domain);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "DNS", Status = ProviderStatus.Success, NormalizedData = "A:" + Environment.NewLine + "93.184.216.34" + Environment.NewLine + "93.184.216.35", Timestamp = DateTimeOffset.UtcNow }
        };

        var relationships = correlationService.Correlate(ioc, results);

        Assert.Equal(2, relationships.Count(r => r.Type == RelationshipType.ResolvesTo));
    }

    [Fact]
    public void Summary_ReturnsExpectedFormat()
    {
        var summaryService = new InvestigationSummaryService();
        var riskAssessment = new RiskAssessment(CreateIoc("192.0.2.1", IocType.IPv4), 75, RiskLevel.High, new List<Evidence> { new Evidence(EvidenceCategory.Reputation, "Test", EvidenceSeverity.High, 20, "VT", DateTimeOffset.UtcNow) }, DateTimeOffset.UtcNow);
        var confidenceAssessment = new ConfidenceAssessment(85, "Test reason");

        var summary = summaryService.GenerateSummary(riskAssessment, confidenceAssessment, riskAssessment.Evidence);

        Assert.Contains("Risk Assessment: High (75/100)", summary);
        Assert.Contains("Confidence: 85%", summary);
        Assert.Contains("Key Evidence:", summary);
        Assert.Contains("Reputation: Test", summary);
    }

    [Fact]
    public async Task AnalysisService_FullPipeline_ReturnsCompleteResult()
    {
        var riskService = new RiskScoringService();
        var confidenceService = new ConfidenceScoringService();
        var correlationService = new IocCorrelationService();
        var summaryService = new InvestigationSummaryService();
        var analysisService = new InvestigationAnalysisService(riskService, confidenceService, correlationService, summaryService);

        var ioc = CreateIoc("example.com", IocType.Domain);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "VirusTotal", Status = ProviderStatus.Success, NormalizedData = "Malicious: 10" + Environment.NewLine + "Reputation: -30", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "AbuseIPDB", Status = ProviderStatus.Success, NormalizedData = "Abuse Confidence: 90%", Timestamp = DateTimeOffset.UtcNow },
            new ProviderResult { ProviderName = "DNS", Status = ProviderStatus.Success, NormalizedData = "A:" + Environment.NewLine + "93.184.216.34", Timestamp = DateTimeOffset.UtcNow }
        };

        var result = await analysisService.AnalyzeAsync(ioc, results);

        Assert.NotNull(result);
        Assert.Same(ioc, result.Ioc);
        Assert.True(result.RiskAssessment.Score > 0);
        Assert.True(result.ConfidenceAssessment.Score > 0);
        Assert.NotEmpty(result.Evidence);
        Assert.NotEmpty(result.Relationships);
        Assert.False(string.IsNullOrWhiteSpace(result.Summary));
    }

    [Fact]
    public async Task AnalysisService_Deterministic_SameInputSameOutput()
    {
        var riskService = new RiskScoringService();
        var confidenceService = new ConfidenceScoringService();
        var correlationService = new IocCorrelationService();
        var summaryService = new InvestigationSummaryService();
        var analysisService = new InvestigationAnalysisService(riskService, confidenceService, correlationService, summaryService);

        var ioc = CreateIoc("example.com", IocType.Domain);
        var results = new List<ProviderResult>
        {
            new ProviderResult { ProviderName = "ThreatFox", Status = ProviderStatus.Success, NormalizedData = "Matches: 1" + Environment.NewLine + "Malware: TestMalware", Timestamp = DateTimeOffset.UtcNow }
        };

        var result1 = await analysisService.AnalyzeAsync(ioc, results);
        var result2 = await analysisService.AnalyzeAsync(ioc, results);

        Assert.Equal(result1.RiskAssessment.Score, result2.RiskAssessment.Score);
        Assert.Equal(result1.ConfidenceAssessment.Score, result2.ConfidenceAssessment.Score);
        Assert.Equal(result1.Evidence.Count, result2.Evidence.Count);
    }

    private sealed class NoOpRateLimiter : IRateLimiter
    {
        public string ProviderName => "NoOp";
        public Task WaitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
