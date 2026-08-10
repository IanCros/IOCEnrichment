namespace IOCX.Domain;

/// <summary>Normalizes an IOC value using rules specific to its type.</summary>
public interface IIocNormalizer
{
    string Normalize(string input, IocType type);
}
