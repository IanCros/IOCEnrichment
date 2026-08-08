namespace IOCX.Application;

/// <summary>Abstraction for passive DNS lookups.</summary>
public interface IDnsResolver
{
    Task<IReadOnlyList<string>> GetAddressesAsync(string hostname, CancellationToken cancellationToken = default);
    Task<DnsHostEntry> GetHostEntryAsync(string hostname, CancellationToken cancellationToken = default);
}

/// <summary>Represents a DNS host entry.</summary>
public sealed class DnsHostEntry
{
    public string HostName { get; init; } = string.Empty;
    public IReadOnlyList<string> Aliases { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Addresses { get; init; } = Array.Empty<string>();
}
