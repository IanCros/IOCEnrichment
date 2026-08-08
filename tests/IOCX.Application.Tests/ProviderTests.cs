namespace IOCX.Application.Tests;

using IOCX.Domain;

/// <summary>Tests for provider framework.</summary>
public class ProviderTests
{
    [Fact]
    public void ProviderRegistry_RegisterAndGetAll_ReturnsRegisteredProviders()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var provider1 = new FakeProvider("Provider1");
        var provider2 = new FakeProvider("Provider2");

        // Act
        registry.Register(provider1);
        registry.Register(provider2);
        var all = registry.GetAll();

        // Assert
        Assert.Equal(2, all.Count);
        Assert.Contains(provider1, all);
        Assert.Contains(provider2, all);
    }

    [Fact]
    public void ProviderRegistry_GetProvidersFor_ReturnsOnlySupportingProviders()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var ipv4Provider = new FakeProvider("IPv4Provider", IocType.IPv4);
        var domainProvider = new FakeProvider("DomainProvider", IocType.Domain);
        var anyProvider = new FakeProvider("AnyProvider");

        registry.Register(ipv4Provider);
        registry.Register(domainProvider);
        registry.Register(anyProvider);

        var ioc = new Ioc("192.0.2.1", "192.0.2.1", IocType.IPv4);

        // Act
        var providers = registry.GetProvidersFor(ioc);

        // Assert
        Assert.Equal(2, providers.Count);
        Assert.Contains(ipv4Provider, providers);
        Assert.Contains(anyProvider, providers);
        Assert.DoesNotContain(domainProvider, providers);
    }

    [Fact]
    public async Task EnrichmentService_EnrichesWithAllApplicableProviders()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var provider1 = new FakeProvider("Provider1", IocType.IPv4);
        var provider2 = new FakeProvider("Provider2", IocType.IPv4);

        registry.Register(provider1);
        registry.Register(provider2);

        var service = new EnrichmentService(registry, new NetworkOptions { MaxConcurrency = 2 });
        var ioc = new Ioc("192.0.2.1", "192.0.2.1", IocType.IPv4);

        // Act
        var results = await service.EnrichAsync(ioc);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.Equal(ProviderStatus.Success, r.Status));
    }

    [Fact]
    public async Task EnrichmentService_ProviderFailure_DoesNotStopOtherProviders()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var goodProvider = new FakeProvider("Good", IocType.IPv4);
        var failingProvider = new FailingProvider("Failing", IocType.IPv4);

        registry.Register(goodProvider);
        registry.Register(failingProvider);

        var service = new EnrichmentService(registry, new NetworkOptions { MaxConcurrency = 2 });
        var ioc = new Ioc("192.0.2.1", "192.0.2.1", IocType.IPv4);

        // Act
        var results = await service.EnrichAsync(ioc);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(results, r => r.ProviderName == "Good" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "Failing" && r.Status == ProviderStatus.Error);
    }

    [Fact]
    public async Task EnrichmentService_Cancellation_ThrowsOperationCanceledException()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var provider = new FakeProvider("Provider", IocType.IPv4);
        registry.Register(provider);

        var service = new EnrichmentService(registry, new NetworkOptions { MaxConcurrency = 1 });
        var ioc = new Ioc("192.0.2.1", "192.0.2.1", IocType.IPv4);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await service.EnrichAsync(ioc, cts.Token));
    }

    [Fact]
    public async Task RateLimiter_RespectsRateLimit()
    {
        // Arrange
        var limiter = new RateLimiter("Test", 2, TimeSpan.FromSeconds(1));
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // Act
        await limiter.WaitAsync();
        await limiter.WaitAsync();
        await limiter.WaitAsync();

        sw.Stop();

        // Assert - should have waited for the third request
        Assert.True(sw.ElapsedMilliseconds >= 900, $"Expected delay but took {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task RateLimiter_Cancellation_ThrowsTaskCanceledException()
    {
        // Arrange
        var limiter = new RateLimiter("Test", 1, TimeSpan.FromSeconds(10));
        await limiter.WaitAsync();

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await limiter.WaitAsync(cts.Token));
    }

    [Fact]
    public void ProviderRegistry_NullProvider_ThrowsArgumentNullException()
    {
        // Arrange
        var registry = new ProviderRegistry();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => registry.Register(null!));
    }

    [Fact]
    public void ProviderRegistry_NullIoc_ThrowsArgumentNullException()
    {
        // Arrange
        var registry = new ProviderRegistry();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => registry.GetProvidersFor(null!));
    }

    [Fact]
    public async Task EnrichmentService_NullIoc_ThrowsArgumentNullException()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var service = new EnrichmentService(registry, new NetworkOptions());

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await service.EnrichAsync(null!));
    }

    private sealed class FakeProvider : IEnrichmentProvider
    {
        public string Name { get; }
        private readonly IocType? _supportedType;

        public FakeProvider(string name, IocType? supportedType = null)
        {
            Name = name;
            _supportedType = supportedType;
        }

        public bool Supports(Ioc ioc)
        {
            if (_supportedType is null) return true;
            return ioc.Type == _supportedType;
        }

        public Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                NormalizedData = $"result from {Name}"
            });
        }
    }

    private sealed class FailingProvider : IEnrichmentProvider
    {
        public string Name { get; }
        private readonly IocType? _supportedType;

        public FailingProvider(string name, IocType? supportedType = null)
        {
            Name = name;
            _supportedType = supportedType;
        }

        public bool Supports(Ioc ioc)
        {
            if (_supportedType is null) return true;
            return ioc.Type == _supportedType;
        }

        public Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Error,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = "Simulated failure"
            });
        }
    }
}
