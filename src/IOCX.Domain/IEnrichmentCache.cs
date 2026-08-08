namespace IOCX.Domain;

using IOCX.Domain.Entities;

/// <summary>Persistent cache of provider responses, keyed by provider and IOC.</summary>
public interface IEnrichmentCache
{
    Task<EnrichmentCacheEntryEntity?> GetAsync(string providerName, IocEntity ioc, CancellationToken cancellationToken = default);

    Task SetAsync(EnrichmentCacheEntryEntity entry, CancellationToken cancellationToken = default);


    Task RemoveAsync(string providerName, IocEntity ioc, CancellationToken cancellationToken = default);


    Task ClearAsync(CancellationToken cancellationToken = default);


    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}
