using System.Windows;

namespace IOCX.Wpf.Services;

/// <summary>Asks the user to confirm a destructive action.</summary>
/// <remarks>
/// Abstracted so view models can request confirmation without referencing
/// <see cref="MessageBox"/>, which would make them untestable and tie deletion logic to WPF.
/// </remarks>
public interface IUserPrompt
{
    /// <summary>Asks the user to confirm an action that cannot be undone.</summary>
    bool ConfirmDestructive(string title, string message);
}

/// <summary>Confirms destructive actions with a standard Windows message box.</summary>
public sealed class MessageBoxUserPrompt : IUserPrompt
{
    /// <inheritdoc />
    public bool ConfirmDestructive(string title, string message) =>
        MessageBox.Show(
            message,
            title,
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning,
            // Default to Cancel so an accidental Enter keypress cannot delete anything.
            MessageBoxResult.Cancel) == MessageBoxResult.OK;
}
