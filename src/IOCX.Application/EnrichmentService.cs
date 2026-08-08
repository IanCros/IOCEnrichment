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

        var providers = _registry.GetProvidersFor(ioc);
        var results = new List<ProviderResult>();
        var tasks = new List<Task<ProviderResult>>();

        foreach (var provider in providers)
        {
            cancellationToken.ThrowIfCancellationRequested();

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
            return results;
        }

        var completed = await Task.WhenAll(tasks);

        return completed.ToList();
    }
}
