namespace IOCX.Application.Configuration;

/// <summary>
/// Reads and writes the user-editable settings layer. The copy shipped beside the executable
/// stays untouched, so a locked-down install directory does not stop the settings screen from
/// saving. API keys go to ISecretStore instead and are never written here.
/// </summary>
public interface IUserSettingsStore
{
    string FilePath { get; }

    /// <summary>Returns defaults when nothing has been saved yet.</summary>
    IocxOptions Load();

    void Save(IocxOptions options);
}
