namespace IOCX.Application.Tests;

using IOCX.Domain;

/// <summary>Covers how providers that cannot answer for a given IOC type are reported.</summary>
/// <remarks>
/// Previously such providers were omitted from the results entirely, which made an
/// IP-only provider queried against a domain indistinguishable from one that silently
/// failed. They are now reported as <see cref="ProviderStatus.Unsupported"/>, and
/// confidence scoring must ignore them rather than treat them as failures.
/// </remarks>
public class UnsupportedProviderReportingTests
{
    private static Ioc Domain() => new("example.com", "example.com", IocType.Domain);
    private static Ioc Ip() => new("192.0.2.1", "192.0.2.1", IocType.IPv4);

    private static ProviderRegistry RegistryWith(params IEnrichmentProvider[] providers)
    {
        var registry = new ProviderRegistry();
        foreach (var provider in providers)
        {
            registry.Register(provider);
        }

        return registry;
    }

    [Fact]
    public async Task Enrichment_ReportsProvidersThatDoNotSupportTheIocType()
    {
        var registry = RegistryWith(
            new FakeProvider("DomainOnly", IocType.Domain),
            new FakeProvider("IpOnly", IocType.IPv4));

        var results = await new EnrichmentService(registry, new NetworkOptions()).EnrichAsync(Domain());

        Assert.Equal(2, results.Count);

        var domainOnly = results.Single(r => r.ProviderName == "DomainOnly");
        Assert.Equal(ProviderStatus.Success, domainOnly.Status);

        var ipOnly = results.Single(r => r.ProviderName == "IpOnly");
        Assert.Equal(ProviderStatus.Unsupported, ipOnly.Status);
        Assert.Contains("Domain", ipOnly.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Enrichment_ReportsEveryRegisteredProviderEvenWhenNoneApply()
    {
        var registry = RegistryWith(
            new FakeProvider("IpOnlyA", IocType.IPv4),
            new FakeProvider("IpOnlyB", IocType.IPv4));

        var results = await new EnrichmentService(registry, new NetworkOptions()).EnrichAsync(Domain());

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.Equal(ProviderStatus.Unsupported, r.Status));
    }

    [Fact]
    public async Task Enrichment_QueriesApplicableProvidersNormally()
    {
        var registry = RegistryWith(
            new FakeProvider("DomainOnly", IocType.Domain),
            new FakeProvider("IpOnly", IocType.IPv4));

        var results = await new EnrichmentService(registry, new NetworkOptions()).EnrichAsync(Ip());

        Assert.Equal(ProviderStatus.Unsupported, results.Single(r => r.ProviderName == "DomainOnly").Status);
        Assert.Equal(ProviderStatus.Success, results.Single(r => r.ProviderName == "IpOnly").Status);
    }

    [Fact]
    public void Confidence_IsNotPenalisedByInapplicableProviders()
    {
        var service = new ConfidenceScoringService();
        var ioc = Domain();

        var withoutUnsupported = new List<ProviderResult>
        {
            Success("A"),
            Success("B")
        };

        var withUnsupported = new List<ProviderResult>
        {
            Success("A"),
            Success("B"),
            new() { ProviderName = "IpOnly1", Status = ProviderStatus.Unsupported, Timestamp = DateTimeOffset.UtcNow },
            new() { ProviderName = "IpOnly2", Status = ProviderStatus.Unsupported, Timestamp = DateTimeOffset.UtcNow }
        };

        var risk = new RiskScoringService().CalculateRisk(ioc, withoutUnsupported);

        var a = service.CalculateConfidence(ioc, withoutUnsupported, risk);
        var b = service.CalculateConfidence(ioc, withUnsupported, risk);

        // Investigating a domain must not score lower confidence than an IP merely because
        // two of the configured providers happen to be IP-only.
        Assert.Equal(a.Score, b.Score);
    }

    [Fact]
    public void Confidence_StillPenalisesGenuineFailures()
    {
        var service = new ConfidenceScoringService();
        var ioc = Domain();

        var healthy = new List<ProviderResult> { Success("A"), Success("B") };

        var degraded = new List<ProviderResult>
        {
            Success("A"),
            new() { ProviderName = "B", Status = ProviderStatus.Timeout, Timestamp = DateTimeOffset.UtcNow }
        };

        var risk = new RiskScoringService().CalculateRisk(ioc, healthy);

        Assert.True(
            service.CalculateConfidence(ioc, degraded, risk).Score
            < service.CalculateConfidence(ioc, healthy, risk).Score);
    }

    private static ProviderResult Success(string name) => new()
    {
        ProviderName = name,
        Status = ProviderStatus.Success,
        Timestamp = DateTimeOffset.UtcNow,
        Findings = new ProviderFindings { Detections = new DetectionFacts(2, 0, 50, 10) }
    };

    private sealed class FakeProvider : IEnrichmentProvider
    {
        private readonly IocType _supported;

        public FakeProvider(string name, IocType supported)
        {
            Name = name;
            _supported = supported;
        }

        public string Name { get; }

        public bool Supports(Ioc ioc) => ioc.Type == _supported;

        public Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                NormalizedData = "ok"
            });
    }
}
