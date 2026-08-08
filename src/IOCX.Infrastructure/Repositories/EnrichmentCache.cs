namespace IOCX.Infrastructure;

using Microsoft.EntityFrameworkCore;
using IOCX.Domain;
using IOCX.Domain.Entities;

/// <summary>EF Core implementation of <see cref="IEnrichmentCache"/>.</summary>
public sealed class EnrichmentCache : IEnrichmentCache
{
    private readonly AppDbContext _context;

    public EnrichmentCache(AppDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task<EnrichmentCacheEntryEntity?> GetAsync(string providerName, IocEntity ioc, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        var entries = await _context.EnrichmentCacheEntries
            .Where(c => c.ProviderName == providerName && c.IocId == ioc.Id)
            .ToListAsync(cancellationToken);

        return entries.FirstOrDefault(c => c.ExpiresAt > now);
    }

    /// <inheritdoc />
    public async Task SetAsync(EnrichmentCacheEntryEntity entry, CancellationToken cancellationToken = default)
    {
        await _context.EnrichmentCacheEntries.AddAsync(entry, cancellationToken);
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string providerName, IocEntity ioc, CancellationToken cancellationToken = default)
    {
        var entry = await _context.EnrichmentCacheEntries
            .FirstOrDefaultAsync(c => c.ProviderName == providerName && c.IocId == ioc.Id, cancellationToken);

        if (entry is not null)
        {
            _context.EnrichmentCacheEntries.Remove(entry);
        }
    }

    /// <inheritdoc />
    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        _context.EnrichmentCacheEntries.RemoveRange(await _context.EnrichmentCacheEntries.ToListAsync(cancellationToken));
    }


    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}
