namespace IOCX.Application;

/// <summary>
/// Default implementation of <see cref="IOCX.Domain.IIocFactory"/> that combines classification, validation, and normalization.
/// </summary>
public sealed class IocFactory : IOCX.Domain.IIocFactory
{
    private readonly IOCX.Domain.IIocClassifier _classifier;
    private readonly IOCX.Domain.IIocNormalizer _normalizer;

    public IocFactory(IOCX.Domain.IIocClassifier classifier, IOCX.Domain.IIocNormalizer normalizer)
    {
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _normalizer = normalizer ?? throw new ArgumentNullException(nameof(normalizer));
    }

    /// <inheritdoc />
    public bool TryCreate(string input, out IOCX.Domain.Ioc? ioc)
    {
        ioc = null;

        if (string.IsNullOrWhiteSpace(input))
            return false;

        var type = _classifier.Classify(input);
        if (type is null)
            return false;

        var normalized = _normalizer.Normalize(input, type.Value);
        if (string.IsNullOrWhiteSpace(normalized))
            return false;

        ioc = new IOCX.Domain.Ioc(input, normalized, type.Value);
        return true;
    }
}
