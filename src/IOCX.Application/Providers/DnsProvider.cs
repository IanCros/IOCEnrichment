namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>DNS enrichment provider using passive DNS lookups.</summary>
public sealed class DnsProvider : IEnrichmentProvider
{
    private readonly IRateLimiter _rateLimiter;
    private readonly IDnsResolver _resolver;

    public DnsProvider(IRateLimiter rateLimiter, IDnsResolver? resolver = null)
    {
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        _resolver = resolver ?? new SystemNetDnsResolver();
    }

    /// <inheritdoc />
    public string Name => "DNS";

    /// <inheritdoc />
    public bool Supports(Ioc ioc)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        return ioc.Type is IocType.Domain or IocType.IPv4 or IocType.IPv6;
    }

    /// <inheritdoc />
    public async Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        if (!Supports(ioc))
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Unsupported,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = $"IOC type {ioc.Type} is not supported by DNS provider."
            };
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);
            var startTime = DateTimeOffset.UtcNow;

            var sb = new System.Text.StringBuilder();

            if (ioc.Type is IocType.Domain)
            {
                await ResolveDomainAsync(ioc.NormalizedValue, sb, cancellationToken);
            }
            else
            {
                try
                {
                    var ptr = await _resolver.GetHostEntryAsync(ioc.NormalizedValue, cancellationToken);
                    sb.AppendLine("PTR:");
                    if (string.IsNullOrEmpty(ptr.HostName) || ptr.HostName == ioc.NormalizedValue)
                    {
                        sb.AppendLine("  (no PTR record)");
                    }
                    else
                    {
                        sb.AppendLine($"  {ptr.HostName}");
                    }
                }
                catch
                {
                    sb.AppendLine("PTR: no PTR record found");
                }
            }

            var duration = (long)(DateTimeOffset.UtcNow - startTime).TotalMilliseconds;

            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                Duration = duration,
                NormalizedData = sb.ToString().TrimEnd()
            };
        }
        catch (OperationCanceledException)
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Timeout,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = "DNS lookup timed out or was canceled."
            };
        }
        catch (Exception ex)
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Error,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = $"DNS error: {ex.Message}"
            };
        }
    }

    private async Task ResolveDomainAsync(string domain, System.Text.StringBuilder sb, CancellationToken cancellationToken)
    {
        // A records
        try
        {
            var aRecords = await _resolver.GetAddressesAsync(domain, cancellationToken);
            if (aRecords.Count > 0)
            {
                sb.AppendLine("A:");
                foreach (var addr in aRecords)
                {
                    sb.AppendLine($"  {addr}");
                }
            }
            else
            {
                sb.AppendLine("A: no records found");
            }
        }
        catch
        {
            sb.AppendLine("A: lookup failed");
        }

        // MX and CNAME via host entry
        try
        {
            var entry = await _resolver.GetHostEntryAsync(domain, cancellationToken);
            if (entry.Addresses.Count > 0)
            {
                sb.AppendLine("MX:");
                foreach (var addr in entry.Addresses)
                {
                    sb.AppendLine($"  {addr}");
                }
            }

            if (entry.Aliases.Count > 0)
            {
                sb.AppendLine("CNAME:");
                foreach (var alias in entry.Aliases)
                {
                    sb.AppendLine($"  {alias}");
                }
            }
        }
        catch
        {
            // No additional records
        }
    }
}
