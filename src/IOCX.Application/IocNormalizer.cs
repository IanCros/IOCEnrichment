namespace IOCX.Application;

using System.Net;

/// <summary>Default implementation of <see cref="IOCX.Domain.IIocNormalizer"/>.</summary>
public sealed class IocNormalizer : IOCX.Domain.IIocNormalizer
{
    /// <inheritdoc />
    public string Normalize(string input, IOCX.Domain.IocType type)
    {
        if (input is null)
            throw new ArgumentNullException(nameof(input));

        var trimmed = input.Trim();

        return type switch
        {
            IOCX.Domain.IocType.IPv4 => NormalizeIpv4(trimmed),
            IOCX.Domain.IocType.IPv6 => NormalizeIpv6(trimmed),
            IOCX.Domain.IocType.Domain => NormalizeDomain(trimmed),
            IOCX.Domain.IocType.Url => NormalizeUrl(trimmed),
            IOCX.Domain.IocType.Md5 or IOCX.Domain.IocType.Sha1 or IOCX.Domain.IocType.Sha256 => NormalizeHash(trimmed),
            IOCX.Domain.IocType.Email => NormalizeEmail(trimmed),
            _ => trimmed,
        };
    }

    private static string NormalizeIpv4(string input)
    {
        if (IPAddress.TryParse(input, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return ip.ToString();

        return input;
    }

    private static string NormalizeIpv6(string input)
    {
        if (IPAddress.TryParse(input, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return ip.ToString();

        return input;
    }

    private static string NormalizeDomain(string input)
    {
        return input.ToLowerInvariant();
    }

    private static string NormalizeUrl(string input)
    {
        if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            var host = uri.Host;
            try
            {
                var hostLower = host.ToLowerInvariant();
                var builder = new UriBuilder(uri)
                {
                    Host = hostLower,
                };
                return builder.Uri.ToString();
            }
            catch
            {
                return input;
            }
        }

        return input;
    }

    private static string NormalizeHash(string input)
    {
        return input.ToLowerInvariant();
    }

    private static string NormalizeEmail(string input)
    {
        var atIndex = input.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == input.Length - 1)
            return input;

        var local = input[..atIndex];
        var domain = input[(atIndex + 1)..];

        return $"{local.ToLowerInvariant()}@{domain.ToLowerInvariant()}";
    }
}
