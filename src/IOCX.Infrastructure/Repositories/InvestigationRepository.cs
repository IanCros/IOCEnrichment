namespace IOCX.Infrastructure;

using Microsoft.EntityFrameworkCore;
using IOCX.Domain;
using IOCX.Domain.Entities;

/// <summary>EF Core implementation of <see cref="IInvestigationRepository"/>.</summary>
public sealed class InvestigationRepository : IInvestigationRepository
{
    private readonly AppDbContext _context;

    public InvestigationRepository(AppDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task AddAsync(InvestigationEntity investigation, CancellationToken cancellationToken = default)
    {
        await _context.Investigations.AddAsync(investigation, cancellationToken);
    }

    /// <inheritdoc />
    public Task UpdateAsync(InvestigationEntity investigation, CancellationToken cancellationToken = default)
    {
        _context.Investigations.Update(investigation);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task<List<InvestigationEntity>> GetByIocIdAsync(Guid iocId, CancellationToken cancellationToken = default)
    {
        var list = await _context.Investigations
            .Where(inv => inv.IocId == iocId)
            .ToListAsync(cancellationToken);

        return list.OrderByDescending(inv => inv.StartedAt).ToList();
    }

    /// <inheritdoc />
    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}
