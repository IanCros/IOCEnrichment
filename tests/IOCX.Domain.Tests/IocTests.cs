namespace IOCX.Domain.Tests;

/// <summary>Unit tests for the <see cref="Ioc"/> domain model.</summary>
public class IocTests
{
    [Fact]
    public void Constructor_WithValidArguments_CreatesInstance()
    {
        // Arrange
        var original = "Example.COM";
        var normalized = "example.com";
        var type = IocType.Domain;

        // Act
        var ioc = new Ioc(original, normalized, type);

        // Assert
        Assert.NotEqual(Guid.Empty, ioc.Id);
        Assert.Equal(original, ioc.OriginalValue);
        Assert.Equal(normalized, ioc.NormalizedValue);
        Assert.Equal(type, ioc.Type);
        Assert.True(ioc.CreatedAt <= DateTimeOffset.UtcNow);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithNullOrWhiteSpaceOriginalValue_ThrowsArgumentException(string? original)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new Ioc(original!, "normalized", IocType.Domain));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithNullOrWhiteSpaceNormalizedValue_ThrowsArgumentException(string? normalized)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new Ioc("original", normalized!, IocType.Domain));
    }
}
