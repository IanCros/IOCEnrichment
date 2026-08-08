namespace IOCX.Domain.Entities;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

/// <summary>EF Core entity representing an IOC record in the database.</summary>
public class IocEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    [MaxLength(2000)]
    public string OriginalValue { get; set; } = string.Empty;

    [Required]
    [MaxLength(2000)]
    public string NormalizedValue { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    public string Type { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? LastInvestigatedAt { get; set; }

    public List<InvestigationEntity> Investigations { get; set; } = new();

    public List<RelationshipEntity> SourceRelationships { get; set; } = new();

    public List<RelationshipEntity> TargetRelationships { get; set; } = new();
}
