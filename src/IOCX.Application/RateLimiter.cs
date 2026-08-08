namespace IOCX.Application;

/// <summary>Simple sliding window rate limiter.</summary>
public sealed class RateLimiter : IRateLimiter
{
    private readonly TimeSpan _window;
    private readonly int _maxRequests;
    private readonly Queue<DateTimeOffset> _requests = new();
    private readonly object _lock = new();

    public RateLimiter(string providerName, int maxRequests, TimeSpan window)
    {
        if (string.IsNullOrWhiteSpace(providerName))
        {
            throw new ArgumentException("Provider name cannot be empty.", nameof(providerName));
        }

        if (maxRequests <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRequests));
        }

        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window));
        }

        ProviderName = providerName;
        _maxRequests = maxRequests;
        _window = window;
    }

    /// <inheritdoc />
    public string ProviderName { get; }

    /// <inheritdoc />
    public async Task WaitAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_lock)
            {
                var now = DateTimeOffset.UtcNow;
                var cutoff = now - _window;

                while (_requests.Count > 0 && _requests.Peek() <= cutoff)
                {
                    _requests.Dequeue();
                }

                if (_requests.Count < _maxRequests)
                {
                    _requests.Enqueue(now);
                    return;
                }
            }

            var waitTime = _window / 10;
            await Task.Delay(waitTime, cancellationToken);
        }
    }
}
