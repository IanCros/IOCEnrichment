namespace IOCX.Application.Configuration;

/// <summary>
/// Root configuration for IOC-X, bound from <c>appsettings.json</c> and environment variables.
/// </summary>
public sealed class IocxOptions
{
    public Dictionary<string, ProviderOptions> Providers { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public CacheOptions Cache { get; set; } = new();

    public NetworkOptions Network { get; set; } = new();

    public ScoringOptions Scoring { get; set; } = new();

    /// <summary>
    /// Gets the options for a provider, falling back to enabled-by-default when the
    /// provider has no explicit entry in configuration.
    /// </summary>
    public ProviderOptions ForProvider(string providerName) =>
        Providers.TryGetValue(providerName, out var options) ? options : new ProviderOptions();
}

/// <summary>Configuration for a single enrichment provider.</summary>
public sealed class ProviderOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Gets or sets the environment variable holding this provider's API key.
    /// Keys are never read from configuration files directly.
    /// </summary>
    public string? ApiKeyEnvironmentVariable { get; set; }

    public int RequestsPerWindow { get; set; } = 4;

    public int WindowSeconds { get; set; } = 15;

    public int? CacheTtlMinutes { get; set; }
}

/// <summary>Configuration for persistent response caching.</summary>
public sealed class CacheOptions
{
    public bool Enabled { get; set; } = true;

    public int DefaultTtlMinutes { get; set; } = 60;

    /// <summary>Gets or sets how long investigation history is retained, in days. Zero keeps it forever.</summary>
    public int InvestigationRetentionDays { get; set; }
}

/// <summary>Risk scoring weights and thresholds.</summary>
/// <remarks>
/// Weights are expressed per signal so an analyst can retune the model without recompiling.
/// See <c>docs/scoring.md</c> for how each signal is derived.
/// </remarks>
public sealed class ScoringOptions
{
    public int LowThreshold { get; set; } = 20;

    public int MediumThreshold { get; set; } = 40;

    public int HighThreshold { get; set; } = 60;

    public int CriticalThreshold { get; set; } = 80;

    public int PerMaliciousDetection { get; set; } = 2;

    public int MaxDetectionScore { get; set; } = 25;

    public int MaxReputationScore { get; set; } = 15;

    public int HighAbuseConfidenceThreshold { get; set; } = 75;

    public int ModerateAbuseConfidenceThreshold { get; set; } = 50;

    public int HighAbuseScore { get; set; } = 20;

    public int ModerateAbuseScore { get; set; } = 10;

    public int PerThreatMatch { get; set; } = 5;

    public int MaxThreatMatchScore { get; set; } = 20;

    public int MalwareAssociationScore { get; set; } = 25;

    public int ProviderAgreementScore { get; set; } = 10;

    public int RecentActivityScore { get; set; } = 10;

    public int RecentActivityWindowDays { get; set; } = 30;
}
