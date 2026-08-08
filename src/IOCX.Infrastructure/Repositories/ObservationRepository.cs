namespace IOCX.Infrastructure;

using Microsoft.EntityFrameworkCore;
using IOCX.Domain;
using IOCX.Domain.Entities;

/// <summary>EF Core implementation of <see cref="IObservationRepository"/>.</summary>
public sealed class ObservationRepository : IObservationRepository
{
    private readonly AppDbContext _context;

    public ObservationRepository(AppDbContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task AddAsync(ProviderObservationEntity observation, CancellationToken cancellationToken = default)
    {
        await _context.Observations.AddAsync(observation, cancellationToken);
    }

    /// <inheritdoc />
    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}
