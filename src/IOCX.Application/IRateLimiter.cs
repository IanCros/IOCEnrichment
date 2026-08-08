namespace IOCX.Application;

/// <summary>Represents a rate limiter for a specific provider.</summary>
public interface IRateLimiter
{
    string ProviderName { get; }

    /// <summary>Waits if necessary to respect rate limits.</summary>
    Task WaitAsync(CancellationToken cancellationToken = default);
}
