namespace IOCX.Application.Providers;

using IOCX.Application.Configuration;
using IOCX.Domain;

/// <summary>Describes why a catalogued provider is or is not available for querying.</summary>
public sealed record ProviderAvailability(
    ProviderDescriptor Descriptor,
    bool IsEnabled,
    bool IsConfigured,
    string Reason)
{
    public bool IsActive => IsEnabled && IsConfigured;

    public string Status => IsActive ? "Active" : Reason;
}

/// <summary>
/// Builds the provider registry from the catalog, configuration, and available credentials.
/// </summary>
/// <remarks>
/// Centralising construction here keeps credential handling and enable/disable logic out of the
/// application bootstrap and out of the providers themselves. A provider that is disabled or
/// missing its key is simply never registered, so the enrichment core never has to reason about
/// credential state.
/// </remarks>
public sealed class ProviderRegistryFactory
{
    private readonly IHttpClient _httpClient;
    private readonly ISecretStore _secretStore;
    private readonly IDnsResolver? _dnsResolver;

    public ProviderRegistryFactory(IHttpClient httpClient, ISecretStore secretStore, IDnsResolver? dnsResolver = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _dnsResolver = dnsResolver;
    }

    /// <summary>
    /// Reports the availability of every catalogued provider, including the ones that will be
    /// skipped, so the settings screen can explain what is and is not running.
    /// </summary>
    public IReadOnlyList<ProviderAvailability> DescribeAvailability(IocxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return ProviderCatalog.All.Select(descriptor =>
        {
            var providerOptions = options.ForProvider(descriptor.Name);
            var hasKey = !descriptor.RequiresApiKey
                         || _secretStore.Has(ResolveKeyName(descriptor, providerOptions));

            var reason = !providerOptions.Enabled
                ? "Disabled"
                : hasKey ? string.Empty : "No API key";

            return new ProviderAvailability(descriptor, providerOptions.Enabled, hasKey, reason);
        }).ToList();
    }

    /// <summary>
    /// Creates a registry containing only the providers that are both enabled and credentialed.
    /// </summary>
    public IProviderRegistry Create(IocxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var registry = new ProviderRegistry();

        foreach (var availability in DescribeAvailability(options).Where(a => a.IsActive))
        {
            var descriptor = availability.Descriptor;
            var providerOptions = options.ForProvider(descriptor.Name);
            var provider = Build(descriptor, providerOptions);

            if (provider is not null)
            {
                registry.Register(provider);
            }
        }

        return registry;
    }

    private static string ResolveKeyName(ProviderDescriptor descriptor, ProviderOptions options) =>
        options.ApiKeyEnvironmentVariable ?? descriptor.ApiKeyEnvironmentVariable!;

    private IEnrichmentProvider? Build(ProviderDescriptor descriptor, ProviderOptions options)
    {
        var limiter = new RateLimiter(
            descriptor.Name,
            options.RequestsPerWindow > 0 ? options.RequestsPerWindow : descriptor.DefaultRequestsPerWindow,
            TimeSpan.FromSeconds(
                options.WindowSeconds > 0 ? options.WindowSeconds : descriptor.DefaultWindowSeconds));

        // The key is read once here and handed to the provider. It is never logged, never
        // written to configuration, and never surfaced through ProviderAvailability.
        var key = descriptor.RequiresApiKey
            ? _secretStore.Get(ResolveKeyName(descriptor, options))
            : null;

        if (descriptor.RequiresApiKey && string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        return descriptor.Name switch
        {
            "VirusTotal" => new VirusTotalProvider(_httpClient, limiter, key!),
            "AbuseIPDB" => new AbuseIpDbProvider(_httpClient, limiter, key!),
            "Shodan" => new ShodanProvider(_httpClient, limiter, key!),
            "ThreatFox" => new ThreatFoxProvider(_httpClient, limiter, key),
            "URLhaus" => new UrlhausProvider(_httpClient, limiter, key),
            "DNS" => new DnsProvider(limiter, _dnsResolver),
            "RDAP" => new RdapProvider(_httpClient, limiter),
            _ => null
        };
    }
}
