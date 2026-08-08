namespace IOCX.Domain;

/// <summary>Classifies a string input into a specific IOC type.</summary>
public interface IIocClassifier
{
    /// <summary>Attempts to classify the provided input as an IOC type.</summary>
    IocType? Classify(string input);
}
