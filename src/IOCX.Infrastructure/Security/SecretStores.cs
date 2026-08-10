namespace IOCX.Infrastructure.Security;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IOCX.Domain;

/// <summary>Read-only secret store backed by process environment variables.</summary>
/// <remarks>
/// This is the deployment-friendly path: CI, containers, and shell profiles can supply keys
/// without the application writing anything to disk.
/// </remarks>
public sealed class EnvironmentSecretStore : ISecretStore
{
    /// <inheritdoc />
    public bool IsWritable => false;

    /// <inheritdoc />
    public string? Get(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <inheritdoc />
    public bool Has(string name) => Get(name) is not null;

    /// <inheritdoc />
    public void Set(string name, string value) =>
        throw new NotSupportedException(
            "Environment variables are read-only. Set the variable in the environment instead.");

    /// <inheritdoc />
    public void Delete(string name) =>
        throw new NotSupportedException(
            "Environment variables are read-only. Unset the variable in the environment instead.");
}

/// <summary>
/// Secret store that encrypts values at rest with Windows DPAPI, scoped to the current user.
/// </summary>
/// <remarks>
/// Encrypted with <see cref="DataProtectionScope.CurrentUser"/>, so the file is readable only
/// by the Windows account that wrote it. Copying it to another machine or account yields
/// nothing. It lives in the roaming profile rather than the repository so credentials cannot
/// be committed by accident.
/// Windows only. Build it through <see cref="SecretStoreFactory"/>, which falls back to an
/// in-memory store elsewhere so the application and tests still run.
/// </remarks>
public sealed class DpapiSecretStore : ISecretStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("IOC-X.SecretStore.v1");

    private readonly string _filePath;
    private readonly object _gate = new();

    public DpapiSecretStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "IOC-X",
            "secrets.dat");
    }

    /// <inheritdoc />
    public bool IsWritable => true;

    /// <inheritdoc />
    public string? Get(string name)
    {
        lock (_gate)
        {
            return Load().TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
                ? value
                : null;
        }
    }

    /// <inheritdoc />
    public bool Has(string name) => Get(name) is not null;

    /// <inheritdoc />
    public void Set(string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        lock (_gate)
        {
            var secrets = Load();
            secrets[name] = value;
            Save(secrets);
        }
    }

    /// <inheritdoc />
    public void Delete(string name)
    {
        lock (_gate)
        {
            var secrets = Load();
            if (secrets.Remove(name))
            {
                Save(secrets);
            }
        }
    }

    private Dictionary<string, string> Load()
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(_filePath))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        try
        {
            var protectedBytes = File.ReadAllBytes(_filePath);
            var plaintext = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(plaintext)
                   ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or IOException)
        {
            // A store written by another user is unreadable by design. Treat it as empty
            // rather than blocking startup. The analyst can re-enter the keys.
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void Save(Dictionary<string, string> secrets)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI secret storage requires Windows.");
        }

        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(secrets);
        var protectedBytes = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_filePath, protectedBytes);
    }
}

/// <summary>Non-persistent store used where DPAPI is unavailable, such as Linux CI runners.</summary>
public sealed class InMemorySecretStore : ISecretStore
{
    private readonly Dictionary<string, string> _secrets = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public bool IsWritable => true;

    /// <inheritdoc />
    public string? Get(string name) =>
        _secrets.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    /// <inheritdoc />
    public bool Has(string name) => Get(name) is not null;

    /// <inheritdoc />
    public void Set(string name, string value) => _secrets[name] = value;

    /// <inheritdoc />
    public void Delete(string name) => _secrets.Remove(name);
}

/// <summary>Reads through an ordered list of stores and writes to the first writable one.</summary>
/// <remarks>
/// Order matters. The environment is consulted first so an operator can always override a
/// stored key without opening the application.
/// </remarks>
public sealed class CompositeSecretStore : ISecretStore
{
    private readonly IReadOnlyList<ISecretStore> _stores;

    public CompositeSecretStore(params ISecretStore[] stores)
    {
        ArgumentNullException.ThrowIfNull(stores);
        if (stores.Length == 0)
        {
            throw new ArgumentException("At least one store is required.", nameof(stores));
        }

        _stores = stores;
    }

    /// <inheritdoc />
    public bool IsWritable => _stores.Any(s => s.IsWritable);

    /// <inheritdoc />
    public string? Get(string name) => _stores.Select(s => s.Get(name)).FirstOrDefault(v => v is not null);

    /// <inheritdoc />
    public bool Has(string name) => _stores.Any(s => s.Has(name));

    /// <inheritdoc />
    public void Set(string name, string value)
    {
        var writable = _stores.FirstOrDefault(s => s.IsWritable)
            ?? throw new NotSupportedException("No writable secret store is configured.");

        writable.Set(name, value);
    }

    /// <inheritdoc />
    public void Delete(string name)
    {
        foreach (var store in _stores.Where(s => s.IsWritable))
        {
            store.Delete(name);
        }
    }

    /// <summary>
    /// Determines whether a secret comes from the environment, which the UI surfaces because
    /// such keys cannot be edited or removed from within the application.
    /// </summary>
    public bool IsSuppliedByEnvironment(string name) =>
        _stores.OfType<EnvironmentSecretStore>().Any(s => s.Has(name));
}

/// <summary>Creates the platform-appropriate secret store.</summary>
public static class SecretStoreFactory
{
    /// <summary>
    /// Creates a store that reads environment variables first and otherwise uses encrypted
    /// local storage, falling back to memory where encryption at rest is unavailable.
    /// </summary>
    public static CompositeSecretStore Create(string? filePath = null) =>
        new(
            new EnvironmentSecretStore(),
            OperatingSystem.IsWindows()
                ? new DpapiSecretStore(filePath)
                : new InMemorySecretStore());
}
