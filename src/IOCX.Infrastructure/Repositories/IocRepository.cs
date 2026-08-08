namespace IOCX.Infrastructure;

using Microsoft.EntityFrameworkCore;
using IOCX.Domain;
using IOCX.Domain.Entities;

/// <summary>EF Core implementation of <see cref="IIocRepository"/>.</summary>
public sealed class IocRepository : IIocRepository
{
    private readonly AppDbContext _context;

    public IocRepository(AppDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task<IocEntity?> GetByNormalizedValueAsync(string normalizedValue, CancellationToken cancellationToken = default)
    {
        return await _context.Iocs
            .FirstOrDefaultAsync(i => i.NormalizedValue == normalizedValue, cancellationToken);
    }

    /// <inheritdoc />
    public async Task AddAsync(IocEntity ioc, CancellationToken cancellationToken = default)
    {
        await _context.Iocs.AddAsync(ioc, cancellationToken);
    }

    /// <inheritdoc />
    public Task UpdateAsync(IocEntity ioc, CancellationToken cancellationToken = default)
    {
        _context.Iocs.Update(ioc);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}
