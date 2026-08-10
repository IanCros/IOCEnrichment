namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Queries every applicable provider for an IOC and collects the results.</summary>
public interface IEnrichmentService
{
    Task<IReadOnlyList<ProviderResult>> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default);
}
