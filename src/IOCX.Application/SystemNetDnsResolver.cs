using System.Net;

namespace IOCX.Application;

/// <summary>Default DNS resolver using System.Net.Dns.</summary>
public sealed class SystemNetDnsResolver : IDnsResolver
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetAddressesAsync(string hostname, CancellationToken cancellationToken = default)
    {
        var addresses = await Dns.GetHostAddressesAsync(hostname, cancellationToken);
        return addresses.Select(a => a.ToString()).ToList();
    }

    /// <inheritdoc />
    public async Task<DnsHostEntry> GetHostEntryAsync(string hostname, CancellationToken cancellationToken = default)
    {
        var entry = await Dns.GetHostEntryAsync(hostname, cancellationToken);
        return new DnsHostEntry
        {
            HostName = entry.HostName,
            Aliases = entry.Aliases.ToList(),
            Addresses = entry.AddressList.Select(a => a.ToString()).ToList()
        };
    }
}
