using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using IOCX.Application;
using IOCX.Wpf.Services;

namespace IOCX.Wpf.ViewModels;

/// <summary>
/// Backs the history screen. Lists stored investigations, supports searching them,
/// and allows deleting them individually or all at once.
/// </summary>
public sealed class HistoryViewModel : INotifyPropertyChanged
{
    private readonly IInvestigationHistoryService _history;
    private readonly IUserPrompt _prompt;

    private List<InvestigationSummary> _all = new();
    private string _statusMessage = string.Empty;
    private string _searchText = string.Empty;
    private bool _isBusy;

    public HistoryViewModel(IInvestigationHistoryService history, IUserPrompt prompt)
    {
        _history = history ?? throw new ArgumentNullException(nameof(history));
        _prompt = prompt ?? throw new ArgumentNullException(nameof(prompt));

        DeleteCommand = new AsyncRelayCommand(
            item => DeleteAsync(item as HistoryItem),
            _ => !IsBusy,
            ex => StatusMessage = $"Could not delete: {ex.Message}");

        ClearAllCommand = new AsyncRelayCommand(
            _ => ClearAllAsync(),
            _ => !IsBusy && _all.Count > 0,
            ex => StatusMessage = $"Could not clear history: {ex.Message}");

        RefreshCommand = new AsyncRelayCommand(
            _ => LoadAsync(),
            _ => !IsBusy,
            ex => StatusMessage = $"Could not load history: {ex.Message}");
    }

    public ObservableCollection<HistoryItem> Items { get; } = new();

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            _searchText = value;
            OnPropertyChanged();
            ApplyFilter();
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set { _isBusy = value; OnPropertyChanged(); }
    }

    public bool IsEmpty => Items.Count == 0;

    public ICommand DeleteCommand { get; }

    public ICommand ClearAllCommand { get; }

    public ICommand RefreshCommand { get; }

    /// <summary>Loads stored investigations.</summary>
    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            IsBusy = true;
            _all = (await _history.GetHistoryAsync(cancellationToken: cancellationToken)).ToList();
            ApplyFilter();

            StatusMessage = _all.Count == 0
                ? "No investigations yet. Analyse an indicator to build history."
                : $"{_all.Count} investigation(s) stored locally.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading history: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task DeleteAsync(HistoryItem? item)
    {
        if (item is null)
        {
            return;
        }

        if (!_prompt.ConfirmDestructive(
                "Delete investigation",
                $"Delete the investigation of {item.Value} from {item.StartedAt:g}?\n\n" +
                "Its provider results and evidence are deleted with it. This cannot be undone."))
        {
            return;
        }

        try
        {
            IsBusy = true;

            if (await _history.DeleteAsync(item.Id))
            {
                _all.RemoveAll(i => i.Id == item.Id);
                ApplyFilter();
                StatusMessage = $"Deleted investigation of {item.Value}.";
            }
            else
            {
                // Something else may have removed it already, so reload instead of insisting.
                StatusMessage = "That investigation no longer exists.";
                await LoadAsync();
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ClearAllAsync()
    {
        if (!_prompt.ConfirmDestructive(
                "Clear all history",
                $"Delete all {_all.Count} stored investigation(s)?\n\n" +
                "Every provider result and evidence item is deleted with them. " +
                "This cannot be undone."))
        {
            return;
        }

        try
        {
            IsBusy = true;
            var deleted = await _history.ClearAllAsync();

            _all.Clear();
            ApplyFilter();
            StatusMessage = $"Deleted {deleted} investigation(s).";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Rebuilds the visible list from the loaded set, applying the search text across the
    /// indicator value, its type, and its risk band.
    /// </summary>
    private void ApplyFilter()
    {
        var term = SearchText?.Trim();

        var filtered = string.IsNullOrEmpty(term)
            ? _all
            : _all.Where(i =>
                i.Value.Contains(term, StringComparison.OrdinalIgnoreCase)
                || i.Type.Contains(term, StringComparison.OrdinalIgnoreCase)
                || i.RiskLevel.Contains(term, StringComparison.OrdinalIgnoreCase)).ToList();

        Items.Clear();
        foreach (var summary in filtered)
        {
            Items.Add(new HistoryItem(summary));
        }

        OnPropertyChanged(nameof(IsEmpty));
    }

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>A row on the history screen.</summary>
public sealed class HistoryItem
{
    internal HistoryItem(InvestigationSummary summary)
    {
        Id = summary.Id;
        Value = summary.Value;
        Type = summary.Type;
        StartedAt = summary.StartedAt;
        CompletedAt = summary.CompletedAt;
        RiskScore = summary.RiskScore;
        RiskLevel = summary.RiskLevel;
        ConfidenceScore = summary.ConfidenceScore;
        ObservationCount = summary.ObservationCount;
    }

    public Guid Id { get; }

    public string Value { get; }

    public string Type { get; }

    public DateTimeOffset StartedAt { get; }

    public DateTimeOffset? CompletedAt { get; }

    public int? RiskScore { get; }

    public string RiskLevel { get; }

    public int? ConfidenceScore { get; }

    public int ObservationCount { get; }
}
