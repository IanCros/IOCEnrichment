namespace IOCX.Application.Tests;

using IOCX.Application.Configuration;
using IOCX.Application.Providers;
using IOCX.Domain;

/// <summary>
/// Tests that configuration and credential state decide which providers get built,
/// and that the settings screen is told why a provider is unavailable.
/// </summary>
public class ProviderCatalogTests
{
    private static ProviderRegistryFactory CreateFactory(ISecretStore secrets) =>
        new(new StubHttpClient(), secrets);

    private static IocxOptions OptionsWith(string provider, bool enabled)
    {
        var options = new IocxOptions();
        options.Providers[provider] = new ProviderOptions { Enabled = enabled };
        return options;
    }

    [Fact]
    public void Catalog_ExposesEveryProviderTheFactoryCanBuild()
    {
        var secrets = new StubSecretStore();

        // Supply a key for every provider that needs one.
        foreach (var descriptor in ProviderCatalog.All.Where(p => p.RequiresApiKey))
        {
            secrets.Set(descriptor.ApiKeyEnvironmentVariable!, "not-a-real-key");
        }

        var registry = CreateFactory(secrets).Create(new IocxOptions());

        Assert.Equal(ProviderCatalog.All.Count, registry.GetAll().Count);
    }

    [Fact]
    public void Catalog_SupportedTypesMatchEachProvidersSupportsMethod()
    {
        var secrets = new StubSecretStore();
        foreach (var descriptor in ProviderCatalog.All.Where(p => p.RequiresApiKey))
        {
            secrets.Set(descriptor.ApiKeyEnvironmentVariable!, "not-a-real-key");
        }

        var registry = CreateFactory(secrets).Create(new IocxOptions());
        var allTypes = Enum.GetValues<IocType>();

        // The registry filters by Supports at query time, so an overstated catalog does not
        // break enrichment. It just misleads whoever reads the settings screen.
        foreach (var provider in registry.GetAll())
        {
            var descriptor = ProviderCatalog.Find(provider.Name);
            Assert.NotNull(descriptor);

            foreach (var type in allTypes)
            {
                var ioc = new Ioc(SampleFor(type), SampleFor(type), type);

                Assert.True(
                    provider.Supports(ioc) == descriptor!.SupportedTypes.Contains(type),
                    $"{provider.Name}: catalog says {type} support is " +
                    $"{descriptor.SupportedTypes.Contains(type)}, but Supports() says {provider.Supports(ioc)}.");
            }
        }
    }

    private static string SampleFor(IocType type) => type switch
    {
        IocType.IPv4 => "192.0.2.1",
        IocType.IPv6 => "2001:db8::1",
        IocType.Domain => "example.com",
        IocType.Url => "https://example.com/a",
        IocType.Md5 => "d41d8cd98f00b204e9800998ecf8427e",
        IocType.Sha1 => "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        IocType.Sha256 => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        IocType.Email => "user@example.com",
        _ => "example.com"
    };

    [Fact]
    public void Catalog_ProviderNamesAreUnique()
    {
        var names = ProviderCatalog.All.Select(p => p.Name).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void KeylessProviders_AreBuiltWithoutCredentials()
    {
        var registry = CreateFactory(new StubSecretStore()).Create(new IocxOptions());

        var built = registry.GetAll().Select(p => p.Name).ToList();

        // ThreatFox, URLhaus, DNS, and RDAP need no credentials and must always be available.
        foreach (var descriptor in ProviderCatalog.All.Where(p => !p.RequiresApiKey))
        {
            Assert.Contains(descriptor.Name, built);
        }
    }

    [Fact]
    public void KeyedProviders_AreSkippedWhenNoCredentialIsPresent()
    {
        var registry = CreateFactory(new StubSecretStore()).Create(new IocxOptions());

        var built = registry.GetAll().Select(p => p.Name).ToList();

        foreach (var descriptor in ProviderCatalog.All.Where(p => p.RequiresApiKey))
        {
            Assert.DoesNotContain(descriptor.Name, built);
        }
    }

    [Fact]
    public void DisabledProvider_IsNotBuiltEvenWithCredentials()
    {
        var secrets = new StubSecretStore();
        secrets.Set("VT_API_KEY", "not-a-real-key");

        var registry = CreateFactory(secrets).Create(OptionsWith("VirusTotal", enabled: false));

        Assert.DoesNotContain("VirusTotal", registry.GetAll().Select(p => p.Name));
    }

    [Fact]
    public void EnabledProviderWithCredentials_IsBuilt()
    {
        var secrets = new StubSecretStore();
        secrets.Set("VT_API_KEY", "not-a-real-key");

        var registry = CreateFactory(secrets).Create(OptionsWith("VirusTotal", enabled: true));

        Assert.Contains("VirusTotal", registry.GetAll().Select(p => p.Name));
    }

    [Fact]
    public void Availability_ExplainsWhyAProviderIsUnavailable()
    {
        var secrets = new StubSecretStore();
        secrets.Set("ABUSEIPDB_API_KEY", "not-a-real-key");

        var options = OptionsWith("Shodan", enabled: false);
        var availability = CreateFactory(secrets).DescribeAvailability(options);

        var virusTotal = availability.Single(a => a.Descriptor.Name == "VirusTotal");
        Assert.False(virusTotal.IsActive);
        Assert.Equal("No API key", virusTotal.Status);

        var shodan = availability.Single(a => a.Descriptor.Name == "Shodan");
        Assert.False(shodan.IsActive);
        Assert.Equal("Disabled", shodan.Status);

        var abuse = availability.Single(a => a.Descriptor.Name == "AbuseIPDB");
        Assert.True(abuse.IsActive);
        Assert.Equal("Active", abuse.Status);
    }

    [Fact]
    public void Availability_NeverExposesTheCredentialItself()
    {
        const string key = "super-secret-value-do-not-leak";
        var secrets = new StubSecretStore();
        secrets.Set("VT_API_KEY", key);

        var availability = CreateFactory(secrets).DescribeAvailability(new IocxOptions());

        Assert.DoesNotContain(availability, a => a.Reason.Contains(key, StringComparison.Ordinal));
        Assert.DoesNotContain(availability, a => a.Status.Contains(key, StringComparison.Ordinal));
    }

    [Fact]
    public void Options_FallBackToEnabledForUnlistedProviders()
    {
        var options = new IocxOptions();

        // A provider with no configuration entry should default to enabled rather than
        // silently disappearing.
        Assert.True(options.ForProvider("ThreatFox").Enabled);
    }

    private sealed class StubSecretStore : ISecretStore
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWritable => true;

        public string? Get(string name) => _values.TryGetValue(name, out var v) ? v : null;

        public bool Has(string name) => Get(name) is not null;

        public void Set(string name, string value) => _values[name] = value;

        public void Delete(string name) => _values.Remove(name);
    }

    /// <summary>
    /// Throws on any request. These tests only assert which providers get constructed,
    /// and the suite must never reach the network.
    /// </summary>
    private sealed class StubHttpClient : IHttpClient
    {
        public Task<HttpResponseResult> GetAsync(
            string url,
            IReadOnlyDictionary<string, string>? headers = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Tests must not perform network requests.");

        public Task<HttpResponseResult> PostAsync(
            string url,
            string? content = null,
            IReadOnlyDictionary<string, string>? headers = null,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Tests must not perform network requests.");

        public void Dispose()
        {
        }
    }
}
