using System.Windows;
using System.Windows.Controls;
using IOCX.Wpf.ViewModels;

namespace IOCX.Wpf.Views;

/// <summary>Dashboard screen showing investigation counts, recent activity, and provider health.</summary>
public partial class DashboardView : UserControl
{
    private readonly DashboardViewModel _viewModel;

    public DashboardView(DashboardViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = _viewModel;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Reloading on every navigation keeps the figures current after new investigations.
        await _viewModel.LoadAsync();
    }
}
