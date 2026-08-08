namespace IOCX.Application.Providers;

/// <summary>Configuration for a threat intelligence provider.</summary>
public sealed class ProviderConfiguration
{
    public bool Enabled { get; set; } = true;

    public string? ApiKeyEnvironmentVariable { get; set; }

    public int? RateLimitPerMinute { get; set; }
}
