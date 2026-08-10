namespace IOCX.Infrastructure.Configuration;

using System.Text.Json;
using System.Text.Json.Serialization;
using IOCX.Application.Configuration;

/// <summary>Stores user-editable settings as JSON under the current user's roaming profile.</summary>
public sealed class JsonUserSettingsStore : IUserSettingsStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true
    };

    public JsonUserSettingsStore(string? filePath = null)
    {
        FilePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "IOC-X",
            "appsettings.json");
    }

    /// <inheritdoc />
    public string FilePath { get; }

    /// <inheritdoc />
    public IocxOptions Load()
    {
        if (!File.Exists(FilePath))
        {
            return new IocxOptions();
        }

        try
        {
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<IocxOptions>(json, SerializerOptions) ?? new IocxOptions();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Corrupt settings must not stop the app starting. Fall back to defaults and
            // let the analyst re-save to repair the file.
            return new IocxOptions();
        }
    }

    /// <inheritdoc />
    public void Save(IocxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Write to a temporary file and swap it in, so an interrupted save cannot leave a
        // half-written settings file behind.
        var tempPath = FilePath + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(options, SerializerOptions));
        File.Move(tempPath, FilePath, overwrite: true);
    }
}
