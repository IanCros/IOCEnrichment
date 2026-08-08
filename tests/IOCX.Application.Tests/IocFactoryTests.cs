namespace IOCX.Application.Tests;

/// <summary>Unit tests for <see cref="IocFactory"/>.</summary>
public class IocFactoryTests
{
    private readonly IocFactory _factory = new(new IocClassifier(), new IocNormalizer());

    [Theory]
    [InlineData("Example.COM", IOCX.Domain.IocType.Domain, "example.com")]
    [InlineData("  Example.COM  ", IOCX.Domain.IocType.Domain, "example.com")]
    public void TryCreate_ValidDomain_ReturnsTrueAndExpectedIoc(string input, IOCX.Domain.IocType expectedType, string expectedNormalized)
    {
        // Act
        var success = _factory.TryCreate(input, out var ioc);

        // Assert
        Assert.True(success);
        Assert.NotNull(ioc);
        Assert.Equal(expectedType, ioc!.Type);
        Assert.Equal(input, ioc.OriginalValue);
        Assert.Equal(expectedNormalized, ioc.NormalizedValue);
    }

    [Theory]
    [InlineData("192.0.2.1", IOCX.Domain.IocType.IPv4, "192.0.2.1")]
    [InlineData("2001:db8::1", IOCX.Domain.IocType.IPv6, "2001:db8::1")]
    public void TryCreate_ValidIpAddress_ReturnsTrueAndExpectedIoc(string input, IOCX.Domain.IocType expectedType, string expectedNormalized)
    {
        // Act
        var success = _factory.TryCreate(input, out var ioc);

        // Assert
        Assert.True(success);
        Assert.NotNull(ioc);
        Assert.Equal(expectedType, ioc!.Type);
        Assert.Equal(input, ioc.OriginalValue);
        Assert.Equal(expectedNormalized, ioc.NormalizedValue);
    }

    [Theory]
    [InlineData("https://example.com/test", IOCX.Domain.IocType.Url, "https://example.com/test")]
    public void TryCreate_ValidUrl_ReturnsTrueAndExpectedIoc(string input, IOCX.Domain.IocType expectedType, string expectedNormalized)
    {
        // Act
        var success = _factory.TryCreate(input, out var ioc);

        // Assert
        Assert.True(success);
        Assert.NotNull(ioc);
        Assert.Equal(expectedType, ioc!.Type);
        Assert.Equal(input, ioc.OriginalValue);
        Assert.Equal(expectedNormalized, ioc.NormalizedValue);
    }

    [Theory]
    [InlineData("d41d8cd98f00b204e9800998ecf8427e", IOCX.Domain.IocType.Md5, "d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCX.Domain.IocType.Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCX.Domain.IocType.Sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    public void TryCreate_ValidHashes_ReturnsTrueAndExpectedIoc(string input, IOCX.Domain.IocType expectedType, string expectedNormalized)
    {
        // Act
        var success = _factory.TryCreate(input, out var ioc);

        // Assert
        Assert.True(success);
        Assert.NotNull(ioc);
        Assert.Equal(expectedType, ioc!.Type);
        Assert.Equal(input, ioc.OriginalValue);
        Assert.Equal(expectedNormalized, ioc.NormalizedValue);
    }

    [Theory]
    [InlineData("user@example.com", IOCX.Domain.IocType.Email, "user@example.com")]
    public void TryCreate_ValidEmail_ReturnsTrueAndExpectedIoc(string input, IOCX.Domain.IocType expectedType, string expectedNormalized)
    {
        // Act
        var success = _factory.TryCreate(input, out var ioc);

        // Assert
        Assert.True(success);
        Assert.NotNull(ioc);
        Assert.Equal(expectedType, ioc!.Type);
        Assert.Equal(input, ioc.OriginalValue);
        Assert.Equal(expectedNormalized, ioc.NormalizedValue);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryCreate_NullOrWhiteSpace_ReturnsFalse(string? input)
    {
        // Act
        var success = _factory.TryCreate(input!, out var ioc);

        // Assert
        Assert.False(success);
        Assert.Null(ioc);
    }

    [Theory]
    [InlineData("not an ioc")]
    [InlineData("example")]
    [InlineData("abc")]
    [InlineData("http://")]
    public void TryCreate_InvalidInput_ReturnsFalse(string input)
    {
        // Act
        var success = _factory.TryCreate(input, out var ioc);

        // Assert
        Assert.False(success);
        Assert.Null(ioc);
    }
}
