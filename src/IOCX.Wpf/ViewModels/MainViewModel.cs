using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows;

namespace IOCX.Wpf.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private readonly IServiceProvider _serviceProvider;
    private object _currentView = null!;

    public object CurrentView
    {
        get => _currentView;
        set { _currentView = value; OnPropertyChanged(); }
    }

    public ICommand NavigateDashboardCommand { get; }
    public ICommand NavigateInvestigateCommand { get; }
    public ICommand NavigateHistoryCommand { get; }
    public ICommand NavigateSettingsCommand { get; }

    public MainViewModel(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;

        NavigateDashboardCommand = new RelayCommand(_ => CurrentView = ResolveView<Views.DashboardView>());
        NavigateInvestigateCommand = new RelayCommand(_ => CurrentView = ResolveView<Views.InvestigationView>());
        NavigateHistoryCommand = new RelayCommand(_ => CurrentView = ResolveView<Views.HistoryView>());
        NavigateSettingsCommand = new RelayCommand(_ => CurrentView = ResolveView<Views.SettingsView>());

        CurrentView = ResolveView<Views.DashboardView>();
    }

    private object ResolveView<T>() where T : class
    {
        return _serviceProvider.GetService(typeof(T)) as T
            ?? throw new InvalidOperationException($"Unable to resolve view {typeof(T)} from DI container.");
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
