namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Registry for enrichment providers.</summary>
public interface IProviderRegistry
{
    /// <summary>Registers a provider.</summary>
    void Register(IEnrichmentProvider provider);

    IReadOnlyList<IEnrichmentProvider> GetAll();

    IReadOnlyList<IEnrichmentProvider> GetProvidersFor(Ioc ioc);
}
