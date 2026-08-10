namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Orchestrates enrichment across multiple providers.</summary>
public sealed class EnrichmentService : IEnrichmentService
{
    private readonly IProviderRegistry _registry;
    private readonly SemaphoreSlim _semaphore;

    public EnrichmentService(IProviderRegistry registry, NetworkOptions options)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        options ??= new NetworkOptions();
        _semaphore = new SemaphoreSlim(options.MaxConcurrency, options.MaxConcurrency);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ProviderResult>> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        var tasks = new List<Task<ProviderResult>>();

        // Report every registered provider, not only the applicable ones. A provider that
        // cannot answer for this IOC type is recorded as Unsupported rather than omitted, so
        // the analyst can see that it was considered and why it contributed nothing —
        // an absent row is indistinguishable from a provider that silently failed.
        var unsupported = new List<ProviderResult>();

        foreach (var provider in _registry.GetAll())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!provider.Supports(ioc))
            {
                unsupported.Add(new ProviderResult
                {
                    ProviderName = provider.Name,
                    Status = ProviderStatus.Unsupported,
                    Timestamp = DateTimeOffset.UtcNow,
                    ErrorMessage = $"Does not support {ioc.Type} indicators."
                });

                continue;
            }

            tasks.Add(Task.Run(async () =>
            {
                await _semaphore.WaitAsync(cancellationToken);
                try
                {
                    return await provider.EnrichAsync(ioc, cancellationToken);
                }
                finally
                {
                    _semaphore.Release();
                }
            }, cancellationToken));
        }

        if (tasks.Count == 0)
        {
            return unsupported;
        }

        var completed = await Task.WhenAll(tasks);

        return [.. completed, .. unsupported];
    }
}
