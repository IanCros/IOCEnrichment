using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using IOCX.Application;
using IOCX.Domain;

namespace IOCX.Wpf.ViewModels;

/// <summary>
/// Backs the investigation screen. Classify an indicator, enrich it across providers,
/// score the result, and store the outcome.
/// </summary>
public sealed class InvestigationViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly IIocFactory _iocFactory;
    private readonly IInvestigationService _investigationService;

    private CancellationTokenSource? _cancellation;

    private string _inputText = string.Empty;
    private string _detectedType = string.Empty;
    private string _normalizedValue = string.Empty;
    private string _originalValue = string.Empty;
    private bool _isAnalyzing;
    private bool _hasResult;
    private string _statusMessage = "Enter an indicator to begin.";
    private string _riskLevel = string.Empty;
    private int _riskScore;
    private int _confidenceScore;
    private string _summary = string.Empty;

    public InvestigationViewModel(IIocFactory iocFactory, IInvestigationService investigationService)
    {
        _iocFactory = iocFactory ?? throw new ArgumentNullException(nameof(iocFactory));
        _investigationService = investigationService ?? throw new ArgumentNullException(nameof(investigationService));

        AnalyzeCommand = new AsyncRelayCommand(
            _ => AnalyzeAsync(),
            _ => !IsAnalyzing && !string.IsNullOrWhiteSpace(InputText),
            ex => StatusMessage = $"Analysis failed: {ex.Message}");

        CancelCommand = new RelayCommand(_ => Cancel(), _ => IsAnalyzing);
    }

    public string InputText
    {
        get => _inputText;
        set { _inputText = value; OnPropertyChanged(); }
    }

    public string DetectedType
    {
        get => _detectedType;
        private set { _detectedType = value; OnPropertyChanged(); }
    }

    public string NormalizedValue
    {
        get => _normalizedValue;
        private set { _normalizedValue = value; OnPropertyChanged(); }
    }

    public string OriginalValue
    {
        get => _originalValue;
        private set { _originalValue = value; OnPropertyChanged(); }
    }

    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        private set { _isAnalyzing = value; OnPropertyChanged(); }
    }

    public bool HasResult
    {
        get => _hasResult;
        private set { _hasResult = value; OnPropertyChanged(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    public string RiskLevel
    {
        get => _riskLevel;
        private set { _riskLevel = value; OnPropertyChanged(); }
    }

    public int RiskScore
    {
        get => _riskScore;
        private set { _riskScore = value; OnPropertyChanged(); }
    }

    public int ConfidenceScore
    {
        get => _confidenceScore;
        private set { _confidenceScore = value; OnPropertyChanged(); }
    }

    public string Summary
    {
        get => _summary;
        private set { _summary = value; OnPropertyChanged(); }
    }

    public ObservableCollection<EvidenceItem> Evidence { get; } = new();

    public ObservableCollection<ProviderResultItem> ProviderResults { get; } = new();

    public ObservableCollection<RelationshipItem> Relationships { get; } = new();

    public ICommand AnalyzeCommand { get; }

    public ICommand CancelCommand { get; }

    private async Task AnalyzeAsync()
    {
        // Replace any previous token source so a cancelled run cannot affect the new one.
        _cancellation?.Dispose();
        _cancellation = new CancellationTokenSource();
        var token = _cancellation.Token;

        IsAnalyzing = true;
        HasResult = false;
        ClearResults();

        try
        {
            StatusMessage = "Classifying indicator...";

            if (!_iocFactory.TryCreate(InputText, out var ioc) || ioc is null)
            {
                StatusMessage = "That does not look like a valid indicator. " +
                                "Enter an IP address, domain, URL, file hash, or email address.";
                return;
            }

            OriginalValue = ioc.OriginalValue;
            NormalizedValue = ioc.NormalizedValue;
            DetectedType = ioc.Type.ToString();

            var progress = new Progress<string>(stage => StatusMessage = stage);
            var outcome = await _investigationService.InvestigateAsync(ioc, progress, token);

            Render(outcome);

            var elapsed = outcome.CompletedAt - outcome.StartedAt;
            StatusMessage = outcome.InvestigationId is null
                ? $"Analysis complete in {elapsed.TotalSeconds:F1}s (not saved)."
                : $"Analysis complete in {elapsed.TotalSeconds:F1}s. Saved to history.";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Investigation cancelled. No further provider requests were made.";
        }
        finally
        {
            IsAnalyzing = false;
        }
    }

    private void Render(InvestigationOutcome outcome)
    {
        // Successes first, then failures, then providers that were not applicable — so the
        // rows that carry evidence are at the top and the noise sinks.
        var ordered = outcome.Results
            .OrderBy(r => r.Status switch
            {
                ProviderStatus.Success => 0,
                ProviderStatus.Unsupported or ProviderStatus.Skipped => 2,
                _ => 1
            })
            .ThenBy(r => r.ProviderName, StringComparer.OrdinalIgnoreCase);

        foreach (var result in ordered)
        {
            var notApplicable = result.Status is ProviderStatus.Unsupported or ProviderStatus.Skipped;

            ProviderResults.Add(new ProviderResultItem(
                result.ProviderName,
                notApplicable ? "Not applicable" : result.Status.ToString(),
                result.Status == ProviderStatus.Success,
                notApplicable,
                result.Duration,
                result.NormalizedData ?? result.ErrorMessage ?? string.Empty));
        }

        RiskScore = outcome.Analysis.RiskAssessment.Score;
        RiskLevel = outcome.Analysis.RiskAssessment.Level.ToString();
        ConfidenceScore = outcome.Analysis.ConfidenceAssessment.Score;
        Summary = outcome.Analysis.Summary;

        foreach (var evidence in outcome.Analysis.Evidence)
        {
            Evidence.Add(new EvidenceItem(
                evidence.Category.ToString(),
                evidence.Description,
                evidence.Severity.ToString(),
                evidence.ScoreContribution,
                evidence.Provider));
        }

        foreach (var relationship in outcome.Analysis.Relationships)
        {
            Relationships.Add(new RelationshipItem(
                relationship.Type.ToString(),
                relationship.Confidence,
                relationship.Provider));
        }

        HasResult = true;
    }

    private void ClearResults()
    {
        Evidence.Clear();
        ProviderResults.Clear();
        Relationships.Clear();
        RiskScore = 0;
        ConfidenceScore = 0;
        RiskLevel = string.Empty;
        Summary = string.Empty;
        DetectedType = string.Empty;
        NormalizedValue = string.Empty;
        OriginalValue = string.Empty;
    }

    private void Cancel()
    {
        // Cancelling the token aborts the in-flight HTTP requests rather than merely
        // detaching the UI from them.
        _cancellation?.Cancel();
        StatusMessage = "Cancelling...";
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _cancellation?.Cancel();
        _cancellation?.Dispose();
        _cancellation = null;
    }

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>An evidence row shown on the investigation screen.</summary>
public sealed record EvidenceItem(
    string Category,
    string Description,
    string Severity,
    int ScoreContribution,
    string Provider);

/// <summary>A per-provider outcome row.</summary>
/// <param name="NotApplicable">
/// Whether the provider was never queried because it does not handle this IOC type. Shown
/// distinctly from a failure, since nothing went wrong.
/// </param>
public sealed record ProviderResultItem(
    string ProviderName,
    string Status,
    bool Succeeded,
    bool NotApplicable,
    long? DurationMs,
    string Data);

/// <summary>A discovered relationship row.</summary>
public sealed record RelationshipItem(string Type, int Confidence, string Provider);
