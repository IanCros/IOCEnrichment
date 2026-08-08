namespace IOCX.Domain;

/// <summary>Supported Indicator of Compromise (IOC) types.</summary>
public enum IocType
{
    /// <summary>IPv4 address.</summary>
    IPv4,

    /// <summary>IPv6 address.</summary>
    IPv6,

    /// <summary>Domain name.</summary>
    Domain,

    /// <summary>Uniform Resource Locator (URL).</summary>
    Url,

    /// <summary>MD5 hash.</summary>
    Md5,

    /// <summary>SHA-1 hash.</summary>
    Sha1,

    /// <summary>SHA-256 hash.</summary>
    Sha256,

    /// <summary>Email address.</summary>
    Email
}
