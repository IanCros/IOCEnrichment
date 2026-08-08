namespace IOCX.Application.Tests;

/// <summary>Unit tests for <see cref="IocClassifier"/>.</summary>
public class IocClassifierTests
{
    private readonly IocClassifier _classifier = new();

    [Theory]
    [InlineData("192.0.2.1", IOCX.Domain.IocType.IPv4)]
    [InlineData("10.0.0.1", IOCX.Domain.IocType.IPv4)]
    [InlineData("172.16.0.1", IOCX.Domain.IocType.IPv4)]
    public void Classify_ValidIPv4_ReturnsIPv4Type(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("2001:db8::1", IOCX.Domain.IocType.IPv6)]
    [InlineData("::1", IOCX.Domain.IocType.IPv6)]
    [InlineData("fe80::1", IOCX.Domain.IocType.IPv6)]
    public void Classify_ValidIPv6_ReturnsIPv6Type(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("example.com", IOCX.Domain.IocType.Domain)]
    [InlineData("sub.example.co.uk", IOCX.Domain.IocType.Domain)]
    [InlineData("Example.COM", IOCX.Domain.IocType.Domain)]
    public void Classify_ValidDomains_ReturnsDomainType(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("https://example.com/test", IOCX.Domain.IocType.Url)]
    [InlineData("http://example.com", IOCX.Domain.IocType.Url)]
    public void Classify_ValidUrls_ReturnsUrlType(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("d41d8cd98f00b204e9800998ecf8427e", IOCX.Domain.IocType.Md5)]
    [InlineData("D41D8CD98F00B204E9800998ECF8427E", IOCX.Domain.IocType.Md5)]
    public void Classify_ValidMd5_ReturnsMd5Type(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCX.Domain.IocType.Sha1)]
    [InlineData("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", IOCX.Domain.IocType.Sha1)]
    public void Classify_ValidSha1_ReturnsSha1Type(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCX.Domain.IocType.Sha256)]
    [InlineData("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", IOCX.Domain.IocType.Sha256)]
    public void Classify_ValidSha256_ReturnsSha256Type(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("user@example.com", IOCX.Domain.IocType.Email)]
    [InlineData("User@Example.COM", IOCX.Domain.IocType.Email)]
    public void Classify_ValidEmails_ReturnsEmailType(string input, IOCX.Domain.IocType expected)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("not an ioc")]
    [InlineData("example")]
    [InlineData("abc")]
    [InlineData("http://")]
    public void Classify_InvalidInput_ReturnsNull(string input)
    {
        // Act
        var result = _classifier.Classify(input);

        // Assert
        Assert.Null(result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Classify_NullOrWhiteSpace_ReturnsNull(string? input)
    {
        // Act
        var result = _classifier.Classify(input!);

        // Assert
        Assert.Null(result);
    }
}
