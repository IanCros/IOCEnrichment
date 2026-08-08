namespace IOCX.Infrastructure;

using Microsoft.EntityFrameworkCore;
using IOCX.Domain;
using IOCX.Domain.Entities;

/// <summary>EF Core implementation of <see cref="IRelationshipRepository"/>.</summary>
public sealed class RelationshipRepository : IRelationshipRepository
{
    private readonly AppDbContext _context;

    public RelationshipRepository(AppDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task AddAsync(RelationshipEntity relationship, CancellationToken cancellationToken = default)
    {
        await _context.Relationships.AddAsync(relationship, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<List<RelationshipEntity>> GetByIocIdAsync(Guid iocId, CancellationToken cancellationToken = default)
    {
        var list = await _context.Relationships
            .Where(r => r.SourceIocId == iocId || r.TargetIocId == iocId)
            .ToListAsync(cancellationToken);

        return list.OrderByDescending(r => r.CreatedAt).ToList();
    }

    /// <inheritdoc />
    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}
