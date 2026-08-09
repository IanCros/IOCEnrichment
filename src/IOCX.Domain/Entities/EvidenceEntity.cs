namespace IOCX.Domain.Entities;

using System.ComponentModel.DataAnnotations;

/// <summary>EF Core entity representing a piece of evidence in an investigation.</summary>
public class EvidenceEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid InvestigationId { get; set; }

    public InvestigationEntity Investigation { get; set; } = null!;

    [Required]
    [MaxLength(50)]
    public string Category { get; set; } = string.Empty;

    [Required]
    public string Description { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    public string Severity { get; set; } = string.Empty;

    public int ScoreContribution { get; set; }

    [Required]
    [MaxLength(100)]
    public string Provider { get; set; } = string.Empty;

    public DateTimeOffset ObservedAt { get; set; }
}
