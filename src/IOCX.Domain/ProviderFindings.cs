namespace IOCX.Domain;

/// <summary>Provider-agnostic facts extracted from an enrichment response.</summary>
/// <remarks>
/// Keeps provider-specific shapes out of the core. Providers translate their own payloads
/// into these fields, and scoring, correlation, and reporting read only from here. Nothing
/// downstream branches on the provider name. Every section is optional because providers
/// cover different aspects of an indicator.
/// </remarks>
public sealed record ProviderFindings
{
    public DetectionFacts? Detections { get; init; }

    public AbuseFacts? Abuse { get; init; }

    public ThreatMatchFacts? ThreatMatches { get; init; }

    public InfrastructureFacts? Infrastructure { get; init; }

    public DnsFacts? Dns { get; init; }

    public RegistrationFacts? Registration { get; init; }

    public IReadOnlyList<RelatedIndicator> Related { get; init; } = Array.Empty<RelatedIndicator>();

    /// <summary>
    /// Gets the most recent malicious activity the provider observed, if it reports one.
    /// Used by the scoring engine to decay stale signals.
    /// </summary>
    public DateTimeOffset? LastActivityAt { get; init; }
}

/// <summary>Detection counts from a provider that aggregates multiple scanning engines.</summary>
public sealed record DetectionFacts(
    int Malicious,
    int Suspicious,
    int Harmless,
    int Undetected,
    int? Reputation = null)
{
    public int TotalEngines => Malicious + Suspicious + Harmless + Undetected;
}

/// <summary>Abuse-report reputation for an address.</summary>
public sealed record AbuseFacts(
    int ConfidencePercent,
    int? TotalReports = null,
    DateTimeOffset? LastReportedAt = null,
    string? UsageType = null);

/// <summary>Matches against a curated threat-intelligence feed.</summary>
public sealed record ThreatMatchFacts(
    int MatchCount,
    IReadOnlyList<string>? MalwareFamilies = null,
    IReadOnlyList<string>? Tags = null,
    DateTimeOffset? FirstSeen = null,
    DateTimeOffset? LastSeen = null,
    bool? IsActive = null)
{
    public IReadOnlyList<string> Families => MalwareFamilies ?? Array.Empty<string>();
}

/// <summary>Network and hosting facts for an address.</summary>
public sealed record InfrastructureFacts(
    string? Organization = null,
    string? Asn = null,
    string? CountryCode = null,
    string? City = null,
    IReadOnlyList<string>? Hostnames = null,
    IReadOnlyList<int>? OpenPorts = null,
    IReadOnlyList<ServiceBanner>? Services = null)
{
    public IReadOnlyList<int> Ports => OpenPorts ?? Array.Empty<int>();

    public IReadOnlyList<ServiceBanner> ObservedServices => Services ?? Array.Empty<ServiceBanner>();
}

/// <summary>A service observed listening on a port.</summary>
public sealed record ServiceBanner(int Port, string? Product = null, string? Version = null, string? Transport = null);

/// <summary>Resolved DNS records for a domain or address.</summary>
public sealed record DnsFacts(IReadOnlyList<DnsRecord> Records)
{
    public IReadOnlyList<string> OfType(string type) =>
        Records.Where(r => string.Equals(r.Type, type, StringComparison.OrdinalIgnoreCase))
               .Select(r => r.Value)
               .ToList();
}

/// <summary>A single DNS record.</summary>
public sealed record DnsRecord(string Type, string Value);

/// <summary>Domain registration facts sourced from RDAP.</summary>
public sealed record RegistrationFacts(
    string? Registrar = null,
    DateTimeOffset? RegisteredAt = null,
    DateTimeOffset? ExpiresAt = null,
    DateTimeOffset? UpdatedAt = null,
    IReadOnlyList<string>? Nameservers = null,
    IReadOnlyList<string>? Statuses = null,
    bool IsPrivacyRedacted = false)
{
    public TimeSpan? AgeAt(DateTimeOffset asOf) =>
        RegisteredAt is { } registered ? asOf - registered : null;
}

/// <summary>An indicator discovered while enriching another indicator.</summary>
public sealed record RelatedIndicator(
    string Value,
    IocType? Type,
    RelationshipType Relationship,
    int Confidence);
