namespace IOCX.Application.Tests;

using IOCX.Domain;
using IOCX.Domain.Entities;
using IOCX.Infrastructure;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Infrastructure tests for persistence and caching.
/// </summary>
public class InfrastructureTests : IAsyncLifetime
{
    private AppDbContext? _context;
    private IIocRepository? _iocRepo;
    private IInvestigationRepository? _investigationRepo;
    private IObservationRepository? _observationRepo;
    private IRelationshipRepository? _relationshipRepo;
    private IEnrichmentCache? _cache;

    public async Task InitializeAsync()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _context = new AppDbContext(options);
        await _context.Database.OpenConnectionAsync();
        await _context.Database.EnsureCreatedAsync();

        _iocRepo = new IOCX.Infrastructure.IocRepository(_context);
        _investigationRepo = new IOCX.Infrastructure.InvestigationRepository(_context);
        _observationRepo = new IOCX.Infrastructure.ObservationRepository(_context);
        _relationshipRepo = new IOCX.Infrastructure.RelationshipRepository(_context);
        _cache = new IOCX.Infrastructure.EnrichmentCache(_context);
    }

    public async Task DisposeAsync()
    {
        if (_context is not null)
        {
            await _context.Database.CloseConnectionAsync();
            await _context.DisposeAsync();
        }
    }

    [Fact]
    public async Task IocRepository_PersistAndRetrieve_ReturnsSameIoc()
    {
        // Arrange
        var ioc = new IocEntity
        {
            Id = Guid.NewGuid(),
            OriginalValue = "Example.COM",
            NormalizedValue = "example.com",
            Type = "Domain",
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Act
        await _iocRepo!.AddAsync(ioc);
        await _iocRepo.SaveChangesAsync();
        var retrieved = await _iocRepo.GetByNormalizedValueAsync("example.com");

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(ioc.Id, retrieved!.Id);
        Assert.Equal("example.com", retrieved.NormalizedValue);
    }

    [Fact]
    public async Task InvestigationRepository_PersistAndRetrieve_ReturnsSameInvestigation()
    {
        // Arrange
        var ioc = new IocEntity
        {
            Id = Guid.NewGuid(),
            OriginalValue = "192.0.2.1",
            NormalizedValue = "192.0.2.1",
            Type = "IPv4",
            CreatedAt = DateTimeOffset.UtcNow
        };
        await _iocRepo!.AddAsync(ioc);
        await _iocRepo.SaveChangesAsync();

        var investigation = new InvestigationEntity
        {
            Id = Guid.NewGuid(),
            IocId = ioc.Id,
            StartedAt = DateTimeOffset.UtcNow,
            RiskScore = 50,
            RiskLevel = "Medium",
            ConfidenceScore = 80
        };

        // Act
        await _investigationRepo!.AddAsync(investigation);
        await _investigationRepo.SaveChangesAsync();
        var retrieved = await _investigationRepo.GetByIocIdAsync(ioc.Id);

        // Assert
        Assert.Single(retrieved);
        Assert.Equal(investigation.Id, retrieved[0].Id);
        Assert.Equal(50, retrieved[0].RiskScore);
    }

    [Fact]
    public async Task RelationshipRepository_PersistAndRetrieve_ReturnsRelationship()
    {
        // Arrange
        var source = new IocEntity { Id = Guid.NewGuid(), OriginalValue = "a.com", NormalizedValue = "a.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };
        var target = new IocEntity { Id = Guid.NewGuid(), OriginalValue = "b.com", NormalizedValue = "b.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };
        await _iocRepo!.AddAsync(source);
        await _iocRepo.AddAsync(target);
        await _iocRepo.SaveChangesAsync();

        var relationship = new RelationshipEntity
        {
            Id = Guid.NewGuid(),
            SourceIocId = source.Id,
            TargetIocId = target.Id,
            RelationshipType = "resolves_to",
            Confidence = 90,
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Act
        await _relationshipRepo!.AddAsync(relationship);
        await _relationshipRepo.SaveChangesAsync();
        var retrieved = await _relationshipRepo.GetByIocIdAsync(source.Id);

        // Assert
        Assert.Single(retrieved);
        Assert.Equal("resolves_to", retrieved[0].RelationshipType);
    }

    [Fact]
    public async Task Cache_SetAndGet_ReturnsCachedEntry()
    {
        // Arrange
        var ioc = new IocEntity { Id = Guid.NewGuid(), NormalizedValue = "test.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };
        await _iocRepo!.AddAsync(ioc);
        await _iocRepo.SaveChangesAsync();

        var entry = new EnrichmentCacheEntryEntity
        {
            Id = Guid.NewGuid(),
            ProviderName = "TestProvider",
            IocId = ioc.Id,
            RetrievedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Result = "{\"risk\":0}"
        };

        // Act
        await _cache!.SetAsync(entry);
        await _cache.SaveChangesAsync();
        var cached = await _cache.GetAsync("TestProvider", ioc);

        // Assert
        Assert.NotNull(cached);
        Assert.Equal(entry.Result, cached!.Result);
    }

    [Fact]
    public async Task Cache_ExpiredEntry_ReturnsNull()
    {
        // Arrange
        var ioc = new IocEntity { Id = Guid.NewGuid(), NormalizedValue = "expire.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };
        await _iocRepo!.AddAsync(ioc);
        await _iocRepo.SaveChangesAsync();

        var entry = new EnrichmentCacheEntryEntity
        {
            Id = Guid.NewGuid(),
            ProviderName = "ExpiredProvider",
            IocId = ioc.Id,
            RetrievedAt = DateTimeOffset.UtcNow.AddHours(-2),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1),
            Result = "old"
        };

        // Act
        await _cache!.SetAsync(entry);
        await _cache.SaveChangesAsync();
        var cached = await _cache.GetAsync("ExpiredProvider", ioc);

        // Assert
        Assert.Null(cached);
    }

    [Fact]
    public async Task Cache_Remove_DeletesEntry()
    {
        // Arrange
        var ioc = new IocEntity { Id = Guid.NewGuid(), NormalizedValue = "remove.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };
        await _iocRepo!.AddAsync(ioc);
        await _iocRepo.SaveChangesAsync();

        var entry = new EnrichmentCacheEntryEntity
        {
            Id = Guid.NewGuid(),
            ProviderName = "RemoveProvider",
            IocId = ioc.Id,
            RetrievedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Result = "remove me"
        };

        // Act
        await _cache!.SetAsync(entry);
        await _cache.SaveChangesAsync();
        await _cache.RemoveAsync("RemoveProvider", ioc);
        await _cache.SaveChangesAsync();
        var cached = await _cache.GetAsync("RemoveProvider", ioc);

        // Assert
        Assert.Null(cached);
    }

    [Fact]
    public async Task DuplicateIoc_UniqueNormalizedValue_ThrowsOnSecondAdd()
    {
        // Arrange
        var ioc1 = new IocEntity { Id = Guid.NewGuid(), NormalizedValue = "dup.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };
        var ioc2 = new IocEntity { Id = Guid.NewGuid(), NormalizedValue = "dup.com", Type = "Domain", CreatedAt = DateTimeOffset.UtcNow };

        // Act
        await _iocRepo!.AddAsync(ioc1);
        await _iocRepo.SaveChangesAsync();
        await _iocRepo.AddAsync(ioc2);

        // Assert
        await Assert.ThrowsAsync<Microsoft.EntityFrameworkCore.DbUpdateException>(async () => await _iocRepo.SaveChangesAsync());
    }
}
