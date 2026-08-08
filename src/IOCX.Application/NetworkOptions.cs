namespace IOCX.Application;

/// <summary>Network configuration options.</summary>
public sealed class NetworkOptions
{
    public int TimeoutSeconds { get; set; } = 15;

    public int MaxConcurrency { get; set; } = 5;
}
