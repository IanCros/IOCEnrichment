using System.Windows.Controls;
using System.Windows;
using IOCX.Wpf.ViewModels;

namespace IOCX.Wpf.Views;

public partial class HistoryView : UserControl
{
    private readonly HistoryViewModel _viewModel;

    public HistoryView(HistoryViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = _viewModel;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await _viewModel.LoadAsync();
    }
}
