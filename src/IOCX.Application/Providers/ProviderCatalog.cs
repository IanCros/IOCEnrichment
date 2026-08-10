namespace IOCX.Application.Providers;

using IOCX.Domain;

/// <summary>
/// Static description of an enrichment provider, independent of whether it is
/// currently enabled or credentialed.
/// </summary>
/// <param name="ApiKeyEnvironmentVariable">
/// The environment variable holding this provider's key, or null when the provider needs no
/// credentials.
/// </param>
public sealed record ProviderDescriptor(
    string Name,
    string Description,
    string? ApiKeyEnvironmentVariable,
    IReadOnlyList<IocType> SupportedTypes,
    int DefaultRequestsPerWindow,
    int DefaultWindowSeconds,
    string DocumentationUrl)
{
    public bool RequiresApiKey => ApiKeyEnvironmentVariable is not null;
}

/// <summary>The set of providers IOC-X knows how to build.</summary>
/// <remarks>
/// This catalog is the single source of truth for provider metadata. Dependency injection uses
/// it to build the registry and the settings screen uses it to list providers with their
/// credential state. Adding a provider means one descriptor and one factory case, with no
/// changes to the UI or the enrichment core.
/// <para>
/// The rate-limit defaults are deliberately conservative rather than each service's published
/// ceiling. They are chosen to stay well inside free-tier allowances. Consult the linked
/// documentation for the current published limits before raising them.
/// </para>
/// </remarks>
public static class ProviderCatalog
{
    private static readonly IocType[] IpTypes = [IocType.IPv4, IocType.IPv6];

    public static IReadOnlyList<ProviderDescriptor> All { get; } =
    [
        new ProviderDescriptor(
            "VirusTotal",
            "Aggregated verdicts from many antivirus engines and URL scanners.",
            "VT_API_KEY",
            [IocType.IPv4, IocType.IPv6, IocType.Domain, IocType.Url, IocType.Md5, IocType.Sha1, IocType.Sha256],
            DefaultRequestsPerWindow: 4,
            DefaultWindowSeconds: 60,
            "https://docs.virustotal.com/reference/overview"),

        new ProviderDescriptor(
            "AbuseIPDB",
            "Community-reported abuse history and confidence rating for IP addresses.",
            "ABUSEIPDB_API_KEY",
            IpTypes,
            DefaultRequestsPerWindow: 4,
            DefaultWindowSeconds: 15,
            "https://docs.abuseipdb.com/"),

        new ProviderDescriptor(
            "Shodan",
            "Previously observed open ports, services, and banners for an address.",
            "SHODAN_API_KEY",
            IpTypes,
            DefaultRequestsPerWindow: 3,
            DefaultWindowSeconds: 15,
            "https://developer.shodan.io/api"),

        // abuse.ch made authentication mandatory for its community APIs. A single free
        // Auth-Key from https://auth.abuse.ch/ covers both ThreatFox and URLhaus, so they
        // share one environment variable.
        new ProviderDescriptor(
            "ThreatFox",
            "abuse.ch feed of indicators tied to named malware families.",
            "ABUSECH_AUTH_KEY",
            [IocType.IPv4, IocType.IPv6, IocType.Domain, IocType.Url, IocType.Md5, IocType.Sha1, IocType.Sha256],
            DefaultRequestsPerWindow: 1,
            DefaultWindowSeconds: 15,
            "https://threatfox.abuse.ch/api/"),

        new ProviderDescriptor(
            "URLhaus",
            "abuse.ch feed of URLs distributing malware payloads.",
            "ABUSECH_AUTH_KEY",
            [IocType.Url, IocType.Domain, IocType.IPv4, IocType.IPv6],
            DefaultRequestsPerWindow: 1,
            DefaultWindowSeconds: 15,
            "https://urlhaus.abuse.ch/api/"),

        // These lists must match each provider's Supports method. The registry filters by
        // Supports at query time, so a mismatch here would not break enrichment, but it would
        // mislead the analyst reading the settings screen.
        new ProviderDescriptor(
            "DNS",
            "Passive resolution of A, AAAA, CNAME, MX, NS, TXT, and PTR records.",
            ApiKeyEnvironmentVariable: null,
            [IocType.Domain, IocType.IPv4, IocType.IPv6],
            DefaultRequestsPerWindow: 10,
            DefaultWindowSeconds: 15,
            "https://datatracker.ietf.org/doc/html/rfc1035"),

        new ProviderDescriptor(
            "RDAP",
            "Registration data for domains and address allocations, honouring privacy redaction.",
            ApiKeyEnvironmentVariable: null,
            [IocType.Domain, IocType.IPv4, IocType.IPv6],
            DefaultRequestsPerWindow: 5,
            DefaultWindowSeconds: 15,
            "https://about.rdap.org/")
    ];

    /// <summary>Finds a descriptor by provider name.</summary>
    public static ProviderDescriptor? Find(string name) =>
        All.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
}
