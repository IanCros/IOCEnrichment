namespace IOCX.Domain.Entities;

using System.ComponentModel.DataAnnotations;

/// <summary>EF Core entity representing an investigation of an IOC.</summary>
public class InvestigationEntity
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid IocId { get; set; }

    public IocEntity Ioc { get; set; } = null!;

    public DateTimeOffset StartedAt { get; set; }

    public DateTimeOffset? CompletedAt { get; set; }

    public int? RiskScore { get; set; }

    [MaxLength(50)]
    public string? RiskLevel { get; set; }

    public int? ConfidenceScore { get; set; }

    public List<ProviderObservationEntity> Observations { get; set; } = new();
}
