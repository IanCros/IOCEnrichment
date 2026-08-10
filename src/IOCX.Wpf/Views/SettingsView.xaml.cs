using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using IOCX.Wpf.ViewModels;

namespace IOCX.Wpf.Views;

/// <summary>
/// Settings screen. Code-behind is limited to the two things that cannot be expressed as
/// bindings. Reading a <see cref="PasswordBox"/>, which deliberately exposes no bindable
/// property, and launching an external browser.
/// </summary>
public partial class SettingsView : UserControl
{
    public SettingsView(SettingsViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    private void OnSaveKeyClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: ProviderSettingsItem item, CommandParameter: PasswordBox box })
        {
            return;
        }

        item.SetKey(box.Password);

        // Clear the box so the key does not linger in a visual element after being stored.
        box.Clear();
    }

    private void OnNavigate(object sender, RequestNavigateEventArgs e)
    {
        // UseShellExecute hands the URI to the OS default browser rather than executing it.
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
