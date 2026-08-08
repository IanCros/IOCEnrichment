namespace IOCX.Application;

using System.Net;
using System.Text.RegularExpressions;

/// <summary>Default implementation of <see cref="IOCX.Domain.IIocClassifier"/>.</summary>
public sealed class IocClassifier : IOCX.Domain.IIocClassifier
{
    private static readonly Regex DomainRegex = new(@"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", RegexOptions.Compiled);
    private const int Md5Length = 32;
    private const int Sha1Length = 40;
    private const int Sha256Length = 64;
    private const int MinEmailLength = 5; // a@b.c

    /// <inheritdoc />
    public IOCX.Domain.IocType? Classify(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        // URLs
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uriResult)
            && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps))
        {
            return IOCX.Domain.IocType.Url;
        }

        // IPv4
        if (IPAddress.TryParse(trimmed, out var ip))
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                return IOCX.Domain.IocType.IPv4;

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return IOCX.Domain.IocType.IPv6;
        }

        // Email
        if (IsEmail(trimmed))
            return IOCX.Domain.IocType.Email;

        // MD5
        if (IsHexHash(trimmed, Md5Length))
            return IOCX.Domain.IocType.Md5;

        // SHA1
        if (IsHexHash(trimmed, Sha1Length))
            return IOCX.Domain.IocType.Sha1;

        // SHA256
        if (IsHexHash(trimmed, Sha256Length))
            return IOCX.Domain.IocType.Sha256;

        // Domain (heuristic. Must contain a dot, not look like a URL path, and match domain regex)
        if (DomainRegex.IsMatch(trimmed))
            return IOCX.Domain.IocType.Domain;

        return null;
    }

    private static bool IsEmail(string input)
    {
        if (input.Length < MinEmailLength)
            return false;

        if (input.Contains(' ') || input.Contains('\t') || input.Contains('\r') || input.Contains('\n'))
            return false;

        var atIndex = input.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == input.Length - 1)
            return false;

        var local = input[..atIndex];
        var domainPart = input[(atIndex + 1)..];

        if (string.IsNullOrEmpty(local) || string.IsNullOrEmpty(domainPart))
            return false;

        // Reject if domain part contains invalid characters
        foreach (var ch in domainPart)
        {
            if (!char.IsLetterOrDigit(ch) && ch != '.' && ch != '-' && ch != '_')
                return false;
        }

        // Must have at least one dot in domain part
        if (!domainPart.Contains('.'))
            return false;

        // Simple local-part validation. Only allow letters, digits, dots, hyphens, underscores, plus
        foreach (var ch in local)
        {
            if (!char.IsLetterOrDigit(ch) && ch != '.' && ch != '-' && ch != '_' && ch != '+')
                return false;
        }

        return true;
    }

    private static bool IsHexHash(string input, int expectedLength)
    {
        if (input.Length != expectedLength)
            return false;

        foreach (var ch in input)
        {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')))
                return false;
        }

        return true;
    }
}
