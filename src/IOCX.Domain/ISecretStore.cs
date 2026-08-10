namespace IOCX.Domain;

/// <summary>
/// Stores provider API keys. Keys never go into configuration files, and nothing in the
/// application logs or displays a value once it has been read.
/// </summary>
public interface ISecretStore
{
    string? Get(string name);

    /// <summary>Checks whether a secret exists without reading it.</summary>
    bool Has(string name);


    void Set(string name, string value);


    void Delete(string name);

    /// <summary>
    /// False for read-only sources such as environment variables, so the UI can explain why
    /// a key cannot be edited here.
    /// </summary>
    bool IsWritable { get; }
}
