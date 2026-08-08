namespace IOCX.Domain.Entities;

using System.ComponentModel.DataAnnotations;

/// <summary>EF Core entity representing an observation from a provider during an investigation.</summary>
public class ProviderObservationEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid InvestigationId { get; set; }

    public InvestigationEntity Investigation { get; set; } = null!;


    [Required]
    [MaxLength(100)]
    public string ProviderName { get; set; } = string.Empty;


    [Required]
    [MaxLength(50)]
    public string Status { get; set; } = string.Empty;

    public DateTimeOffset RetrievedAt { get; set; }

    public long? Duration { get; set; }

    public string? NormalizedResult { get; set; }
}
