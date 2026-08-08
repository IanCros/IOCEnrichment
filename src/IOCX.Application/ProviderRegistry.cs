namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Simple in-memory registry for enrichment providers.</summary>
public sealed class ProviderRegistry : IProviderRegistry
{
    private readonly List<IEnrichmentProvider> _providers = new();

    /// <inheritdoc />
    public void Register(IEnrichmentProvider provider)
    {
        if (provider is null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        _providers.Add(provider);
    }

    /// <inheritdoc />
    public IReadOnlyList<IEnrichmentProvider> GetAll()
    {
        return _providers.ToList();
    }

    /// <inheritdoc />
    public IReadOnlyList<IEnrichmentProvider> GetProvidersFor(Ioc ioc)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        return _providers.Where(p => p.Supports(ioc)).ToList();
    }
}
