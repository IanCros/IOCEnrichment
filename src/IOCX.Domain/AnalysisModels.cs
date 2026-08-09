namespace IOCX.Domain;

/// <summary>Represents the severity level of evidence.</summary>
public enum EvidenceSeverity
{
    /// <summary>Informational evidence.</summary>
    Informational = 0,
    /// <summary>Low severity evidence.</summary>
    Low = 1,
    /// <summary>Medium severity evidence.</summary>
    Medium = 2,
    /// <summary>High severity evidence.</summary>
    High = 3,
    /// <summary>Critical severity evidence.</summary>
    Critical = 4
}

/// <summary>Represents the category of evidence.</summary>
public enum EvidenceCategory
{
    Reputation,
    MalwareAssociation,
    ThreatIntelligence,
    AbuseReports,
    Infrastructure,
    Correlation,
    Recency,
    ProviderAgreement,
    Registration,
    Dns
}

/// <summary>Represents a piece of evidence contributing to a risk assessment.</summary>
public record Evidence(EvidenceCategory Category, string Description, EvidenceSeverity Severity, int ScoreContribution, string Provider, DateTimeOffset Timestamp);

/// <summary>Represents the risk level derived from a numeric score.</summary>
public enum RiskLevel
{
    /// <summary>0-19: Informational risk.</summary>
    Informational = 0,
    /// <summary>20-39: Low risk.</summary>
    Low = 20,
    /// <summary>40-59: Medium risk.</summary>
    Medium = 40,
    /// <summary>60-79: High risk.</summary>
    High = 60,
    /// <summary>80-100: Critical risk.</summary>
    Critical = 80
}

/// <summary>Represents a complete risk assessment for an IOC.</summary>
public sealed record RiskAssessment(Ioc Ioc, int Score, RiskLevel Level, IReadOnlyCollection<Evidence> Evidence, DateTimeOffset AnalyzedAt);

/// <summary>Represents a confidence assessment for an analysis result.</summary>
public sealed record ConfidenceAssessment(int Score, string Reason);

/// <summary>Represents a relationship between two IOCs.</summary>
public sealed record IocRelationship(Guid SourceIocId, Guid TargetIocId, RelationshipType Type, int Confidence, string Provider, DateTimeOffset ObservedAt);

/// <summary>Represents the type of relationship between IOCs.</summary>
public enum RelationshipType
{
    ResolvesTo,
    HostedOn,
    AssociatedWith,
    BelongsToAsn,
    HasNameserver,
    HasMailServer,
    ExposesService,
    AssociatedWithMalware,
    RelatedTo
}
