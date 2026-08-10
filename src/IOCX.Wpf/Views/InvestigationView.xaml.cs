using System.Windows.Controls;
using IOCX.Wpf.ViewModels;

namespace IOCX.Wpf.Views;

public partial class InvestigationView : UserControl
{
    public InvestigationView(InvestigationViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
