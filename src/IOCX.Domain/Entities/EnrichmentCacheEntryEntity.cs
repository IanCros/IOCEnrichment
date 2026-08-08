namespace IOCX.Domain.Entities;

using System.ComponentModel.DataAnnotations;

/// <summary>EF Core entity representing a cached enrichment result.</summary>
public class EnrichmentCacheEntryEntity
{
    [Key]
    public Guid Id { get; set; }


    [Required]
    [MaxLength(100)]
    public string ProviderName { get; set; } = string.Empty;

    [Required]
    public Guid IocId { get; set; }

    public IocEntity Ioc { get; set; } = null!;

    public DateTimeOffset RetrievedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    [Required]
    public string Result { get; set; } = string.Empty;
}
