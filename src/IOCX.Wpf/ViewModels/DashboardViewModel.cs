using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using IOCX.Application;
using IOCX.Application.Configuration;
using IOCX.Application.Providers;

namespace IOCX.Wpf.ViewModels;

/// <summary>
/// Backs the dashboard. Investigation counts by risk band, recent activity, and
/// which providers are currently able to answer queries.
/// </summary>
public sealed class DashboardViewModel : INotifyPropertyChanged
{
    private readonly IInvestigationHistoryService _history;
    private readonly ProviderRegistryFactory _registryFactory;
    private readonly IocxOptions _options;

    private int _totalInvestigations;
    private int _criticalCount;
    private int _highCount;
    private int _mediumCount;
    private int _lowCount;
    private string _statusMessage = string.Empty;

    public DashboardViewModel(
        IInvestigationHistoryService history,
        ProviderRegistryFactory registryFactory,
        IocxOptions options)
    {
        _history = history ?? throw new ArgumentNullException(nameof(history));
        _registryFactory = registryFactory ?? throw new ArgumentNullException(nameof(registryFactory));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public int TotalInvestigations
    {
        get => _totalInvestigations;
        private set { _totalInvestigations = value; OnPropertyChanged(); }
    }

    public int CriticalCount
    {
        get => _criticalCount;
        private set { _criticalCount = value; OnPropertyChanged(); }
    }

    public int HighCount
    {
        get => _highCount;
        private set { _highCount = value; OnPropertyChanged(); }
    }

    public int MediumCount
    {
        get => _mediumCount;
        private set { _mediumCount = value; OnPropertyChanged(); }
    }

    public int LowCount
    {
        get => _lowCount;
        private set { _lowCount = value; OnPropertyChanged(); }
    }

    public bool IsEmpty => TotalInvestigations == 0;

    public ObservableCollection<RecentInvestigationItem> Recent { get; } = new();

    public ObservableCollection<ProviderHealthItem> ProviderHealth { get; } = new();

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    /// <summary>
    /// Loads dashboard data. Called when the view is shown so the figures reflect any
    /// investigations run since the last visit.
    /// </summary>
    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        LoadProviderHealth();

        try
        {
            var statistics = await _history.GetStatisticsAsync(cancellationToken);

            TotalInvestigations = statistics.Total;
            CriticalCount = statistics.Critical;
            HighCount = statistics.High;
            MediumCount = statistics.Medium;
            LowCount = statistics.LowOrInformational;

            Recent.Clear();
            foreach (var investigation in await _history.GetHistoryAsync(8, cancellationToken))
            {
                Recent.Add(new RecentInvestigationItem(
                    investigation.Value,
                    investigation.Type,
                    investigation.RiskLevel,
                    investigation.RiskScore,
                    investigation.ConfidenceScore,
                    investigation.StartedAt));
            }

            OnPropertyChanged(nameof(IsEmpty));

            StatusMessage = TotalInvestigations == 0
                ? "No investigations yet. Open the Investigate tab to analyse your first indicator."
                : $"{TotalInvestigations} investigation(s) stored locally.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not load dashboard data: {ex.Message}";
        }
    }

    private void LoadProviderHealth()
    {
        ProviderHealth.Clear();

        foreach (var availability in _registryFactory.DescribeAvailability(_options))
        {
            ProviderHealth.Add(new ProviderHealthItem(
                availability.Descriptor.Name,
                availability.Status,
                availability.IsActive));
        }
    }

    private static bool IsLevel(string? stored, string level) =>
        string.Equals(stored, level, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>A row in the dashboard's recent-investigations list.</summary>
public sealed record RecentInvestigationItem(
    string Value,
    string Type,
    string RiskLevel,
    int? RiskScore,
    int? ConfidenceScore,
    DateTimeOffset StartedAt);

/// <summary>A row in the dashboard's provider health list.</summary>
public sealed record ProviderHealthItem(string Name, string Status, bool IsActive);
