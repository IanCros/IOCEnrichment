namespace IOCX.Domain;

/// <summary>Builds an <see cref="Ioc"/> from raw input, classifying and normalizing it.</summary>
public interface IIocFactory
{
    /// <summary>Returns false when the input is not a recognisable indicator.</summary>
    bool TryCreate(string input, out Ioc? ioc);
}
