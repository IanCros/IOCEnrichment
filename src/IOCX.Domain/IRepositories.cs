namespace IOCX.Domain;

using IOCX.Domain.Entities;


/// <summary>Repository for IocEntity persistence.</summary>
public interface IIocRepository
{
    Task<IocEntity?> GetByNormalizedValueAsync(string normalizedValue, CancellationToken cancellationToken = default);

    /// <summary>Adds a new IOC.</summary>
    Task AddAsync(IocEntity ioc, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing IOC.</summary>
    Task UpdateAsync(IocEntity ioc, CancellationToken cancellationToken = default);

    /// <summary>Saves changes.</summary>
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}

/// <summary>Repository for InvestigationEntity persistence.</summary>
public interface IInvestigationRepository
{
    /// <summary>Adds a new investigation.</summary>
    Task AddAsync(InvestigationEntity investigation, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing investigation.</summary>
    Task UpdateAsync(InvestigationEntity investigation, CancellationToken cancellationToken = default);

    Task<List<InvestigationEntity>> GetByIocIdAsync(Guid iocId, CancellationToken cancellationToken = default);

    /// <summary>Saves changes.</summary>
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}

/// <summary>Repository for ProviderObservationEntity persistence.</summary>
public interface IObservationRepository
{
    /// <summary>Adds a new observation.</summary>
    Task AddAsync(ProviderObservationEntity observation, CancellationToken cancellationToken = default);

    /// <summary>Saves changes.</summary>
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}

/// <summary>Repository for RelationshipEntity persistence.</summary>
public interface IRelationshipRepository
{
    /// <summary>Adds a new relationship.</summary>
    Task AddAsync(RelationshipEntity relationship, CancellationToken cancellationToken = default);

    Task<List<RelationshipEntity>> GetByIocIdAsync(Guid iocId, CancellationToken cancellationToken = default);

    /// <summary>Saves changes.</summary>
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}
