using System.Windows;
using IOCX.Wpf.ViewModels;

namespace IOCX.Wpf.Views;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
