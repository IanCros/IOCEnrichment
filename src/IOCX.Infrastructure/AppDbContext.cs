namespace IOCX.Infrastructure;

using Microsoft.EntityFrameworkCore;
using IOCX.Domain.Entities;

/// <summary>EF Core DbContext for IOC-X.</summary>
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<IocEntity> Iocs => Set<IocEntity>();

    public DbSet<InvestigationEntity> Investigations => Set<InvestigationEntity>();

    public DbSet<ProviderObservationEntity> Observations => Set<ProviderObservationEntity>();

    public DbSet<RelationshipEntity> Relationships => Set<RelationshipEntity>();

    public DbSet<EnrichmentCacheEntryEntity> EnrichmentCacheEntries => Set<EnrichmentCacheEntryEntity>();

    /// <summary>
    /// Gets the Evidence DbSet. Evidence is stored per investigation so a historical
    /// assessment can be re-read with the reasoning that produced it.
    /// </summary>
    public DbSet<EvidenceEntity> Evidence => Set<EvidenceEntity>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Evidence
        modelBuilder.Entity<EvidenceEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Category).IsRequired().HasMaxLength(50);
            entity.Property(e => e.Description).IsRequired();
            entity.Property(e => e.Severity).IsRequired().HasMaxLength(50);
            entity.Property(e => e.Provider).IsRequired().HasMaxLength(100);

            entity.HasOne(e => e.Investigation)
                .WithMany()
                .HasForeignKey(e => e.InvestigationId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(e => e.InvestigationId);
        });

        // IOC
        modelBuilder.Entity<IocEntity>(entity =>
        {
            entity.HasKey(i => i.Id);
            entity.Property(i => i.OriginalValue).IsRequired().HasMaxLength(2000);
            entity.Property(i => i.NormalizedValue).IsRequired().HasMaxLength(2000);
            entity.Property(i => i.Type).IsRequired().HasMaxLength(50);
            entity.Property(i => i.CreatedAt);
            entity.Property(i => i.LastInvestigatedAt);

            entity.HasIndex(i => i.NormalizedValue).IsUnique();
            entity.HasIndex(i => i.Type);
        });

        // Investigation
        modelBuilder.Entity<InvestigationEntity>(entity =>
        {
            entity.HasKey(inv => inv.Id);
            entity.Property(inv => inv.StartedAt);
            entity.Property(inv => inv.CompletedAt);
            entity.Property(inv => inv.RiskScore);
            entity.Property(inv => inv.RiskLevel).HasMaxLength(50);
            entity.Property(inv => inv.ConfidenceScore);

            entity.HasOne(inv => inv.Ioc)
                .WithMany(i => i.Investigations)
                .HasForeignKey(inv => inv.IocId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(inv => inv.IocId);
        });

        // ProviderObservation
        modelBuilder.Entity<ProviderObservationEntity>(entity =>
        {
            entity.HasKey(obs => obs.Id);
            entity.Property(obs => obs.ProviderName).IsRequired().HasMaxLength(100);
            entity.Property(obs => obs.Status).IsRequired().HasMaxLength(50);
            entity.Property(obs => obs.RetrievedAt);
            entity.Property(obs => obs.Duration);
            entity.Property(obs => obs.NormalizedResult);

            entity.HasOne(obs => obs.Investigation)
                .WithMany(inv => inv.Observations)
                .HasForeignKey(obs => obs.InvestigationId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(obs => obs.InvestigationId);
        });

        // Relationship
        modelBuilder.Entity<RelationshipEntity>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.Property(r => r.RelationshipType).IsRequired().HasMaxLength(100);
            entity.Property(r => r.Confidence);
            entity.Property(r => r.CreatedAt);

            entity.HasOne(r => r.SourceIoc)
                .WithMany(i => i.SourceRelationships)
                .HasForeignKey(r => r.SourceIocId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(r => r.TargetIoc)
                .WithMany(i => i.TargetRelationships)
                .HasForeignKey(r => r.TargetIocId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(r => r.SourceIocId);
            entity.HasIndex(r => r.TargetIocId);
        });

        // EnrichmentCacheEntry
        modelBuilder.Entity<EnrichmentCacheEntryEntity>(entity =>
        {
            entity.HasKey(c => c.Id);
            entity.Property(c => c.ProviderName).IsRequired().HasMaxLength(100);
            entity.Property(c => c.RetrievedAt);
            entity.Property(c => c.ExpiresAt);
            entity.Property(c => c.Result).IsRequired();

            entity.HasOne(c => c.Ioc)
                .WithMany()
                .HasForeignKey(c => c.IocId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(c => new { c.ProviderName, c.IocId }).IsUnique();
            entity.HasIndex(c => c.ExpiresAt);
        });
    }
}
