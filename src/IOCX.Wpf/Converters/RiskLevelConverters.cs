using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace IOCX.Wpf.Converters;

/// <summary>The colour assigned to each risk band.</summary>
/// <remarks>
/// Defined once so every screen agrees. Colour always accompanies the band name in text,
/// never replaces it, so the rating stays readable without relying on colour perception.
/// </remarks>
public static class RiskPalette
{
    public static SolidColorBrush Accent(string? riskLevel) => riskLevel?.Trim().ToLowerInvariant() switch
    {
        "critical" => Frozen(0xE0, 0x5C, 0x5C),
        "high" => Frozen(0xE0, 0xA3, 0x3C),
        "medium" => Frozen(0xE0, 0xD2, 0x3C),
        "low" => Frozen(0x6F, 0xCF, 0x5A),
        "informational" => Frozen(0x6F, 0xA8, 0xDC),
        _ => Frozen(0x9E, 0x9E, 0x9E)
    };

    public static SolidColorBrush Fill(string? riskLevel)
    {
        var accent = Accent(riskLevel).Color;
        return Frozen(accent.R, accent.G, accent.B, 0x33);
    }

    private static SolidColorBrush Frozen(byte r, byte g, byte b, byte a = 0xFF)
    {
        var brush = new SolidColorBrush(Color.FromArgb(a, r, g, b));
        brush.Freeze();
        return brush;
    }
}

/// <summary>Converts a risk band name to its accent brush, for text and borders.</summary>
public sealed class RiskLevelToBrushConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        RiskPalette.Accent(value as string);

    /// <inheritdoc />
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException("Risk colours are display-only.");
}

/// <summary>Converts a risk band name to a muted fill brush, for badge backgrounds.</summary>
public sealed class RiskLevelToFillConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        RiskPalette.Fill(value as string);

    /// <inheritdoc />
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException("Risk colours are display-only.");
}
