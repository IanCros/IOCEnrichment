namespace IOCX.Domain;

/// <summary>Represents an immutable Indicator of Compromise (IOC).</summary>
public sealed class Ioc
{
    public Guid Id { get; }

    public string OriginalValue { get; }

    public string NormalizedValue { get; }

    public IocType Type { get; }

    public DateTimeOffset CreatedAt { get; }

    public Ioc(string originalValue, string normalizedValue, IocType type)
    {
        if (string.IsNullOrWhiteSpace(originalValue))
            throw new ArgumentException("Original value cannot be null or whitespace.", nameof(originalValue));

        if (string.IsNullOrWhiteSpace(normalizedValue))
            throw new ArgumentException("Normalized value cannot be null or whitespace.", nameof(normalizedValue));

        Id = Guid.NewGuid();
        OriginalValue = originalValue;
        NormalizedValue = normalizedValue;
        Type = type;
        CreatedAt = DateTimeOffset.UtcNow;
    }
}
