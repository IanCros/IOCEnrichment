namespace IOCX.Application.Tests;

/// <summary>Unit tests for <see cref="IocNormalizer"/>.</summary>
public class IocNormalizerTests
{
    private readonly IocNormalizer _normalizer = new();

    [Theory]
    [InlineData("192.0.2.1", IOCX.Domain.IocType.IPv4, "192.0.2.1")]
    [InlineData("10.0.0.1", IOCX.Domain.IocType.IPv4, "10.0.0.1")]
    public void Normalize_ValidIPv4_ReturnsTrimmedLowercase(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("2001:db8::1", IOCX.Domain.IocType.IPv6, "2001:db8::1")]
    [InlineData(" ::1 ", IOCX.Domain.IocType.IPv6, "::1")]
    public void Normalize_ValidIPv6_ReturnsTrimmedNormalized(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("Example.COM", IOCX.Domain.IocType.Domain, "example.com")]
    [InlineData("  Example.COM  ", IOCX.Domain.IocType.Domain, "example.com")]
    public void Normalize_Domain_ReturnsLowercaseTrimmed(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("https://Example.COM/test", IOCX.Domain.IocType.Url, "https://example.com/test")]
    [InlineData("HTtp://Example.COM", IOCX.Domain.IocType.Url, "http://example.com/")]
    public void Normalize_Url_ReturnsLowercaseHost(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("D41D8CD98F00B204E9800998ECF8427E", IOCX.Domain.IocType.Md5, "d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData("  D41D8CD98F00B204E9800998ECF8427E  ", IOCX.Domain.IocType.Md5, "d41d8cd98f00b204e9800998ecf8427e")]
    public void Normalize_Md5_ReturnsLowercaseTrimmed(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", IOCX.Domain.IocType.Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709")]
    public void Normalize_Sha1_ReturnsLowercaseTrimmed(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", IOCX.Domain.IocType.Sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    public void Normalize_Sha256_ReturnsLowercaseTrimmed(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("User@Example.COM", IOCX.Domain.IocType.Email, "user@example.com")]
    [InlineData("  User@Example.COM  ", IOCX.Domain.IocType.Email, "user@example.com")]
    public void Normalize_Email_ReturnsLowercaseTrimmed(string input, IOCX.Domain.IocType type, string expected)
    {
        // Act
        var result = _normalizer.Normalize(input, type);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void Normalize_NullInput_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _normalizer.Normalize(null!, IOCX.Domain.IocType.Domain));
    }
}
