namespace IOCX.Domain.Entities;

using System.ComponentModel.DataAnnotations;

/// <summary>EF Core entity representing a relationship between two IOCs.</summary>
public class RelationshipEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid SourceIocId { get; set; }

    public IocEntity SourceIoc { get; set; } = null!;

    [Required]
    public Guid TargetIocId { get; set; }

    public IocEntity TargetIoc { get; set; } = null!;


    [Required]
    [MaxLength(100)]
    public string RelationshipType { get; set; } = string.Empty;

    public int? Confidence { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
