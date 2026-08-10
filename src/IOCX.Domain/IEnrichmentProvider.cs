namespace IOCX.Domain;

/// <summary>The outcome of a single provider request.</summary>
public sealed class ProviderResult
{
    public string ProviderName { get; init; } = string.Empty;

    public ProviderStatus Status { get; init; }

    public DateTimeOffset Timestamp { get; init; }

    public long? Duration { get; init; }

    public string? NormalizedData { get; init; }

    /// <summary>
    /// Structured facts from the response. Scoring, correlation, and reporting read this.
    /// NormalizedData is for display only and nothing should parse it.
    /// </summary>
    public ProviderFindings? Findings { get; init; }

    public string? ErrorMessage { get; init; }
}

/// <summary>How a provider request ended. Only Success carries usable data.</summary>
public enum ProviderStatus
{
    /// <summary>The request succeeded.</summary>
    Success,

    /// <summary>Not queried, by configuration.</summary>
    Skipped,

    /// <summary>The request was unauthorized (401).</summary>
    Unauthorized,

    /// <summary>The request was rate limited (429).</summary>
    RateLimited,

    /// <summary>The request timed out.</summary>
    Timeout,

    /// <summary>The provider was unavailable.</summary>
    Unavailable,

    /// <summary>The response was invalid or malformed.</summary>
    InvalidResponse,

    /// <summary>Not queried, because the provider cannot answer for this IOC type.</summary>
    Unsupported,

    /// <summary>An error occurred during the request.</summary>
    Error
}

/// <summary>A single intelligence source. Implementations translate their own API shape
/// into ProviderFindings so nothing provider-specific escapes into the core.</summary>
public interface IEnrichmentProvider
{
    string Name { get; }

    bool Supports(Ioc ioc);

    Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default);
}
