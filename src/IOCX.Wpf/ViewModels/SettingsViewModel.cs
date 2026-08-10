using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using IOCX.Application.Configuration;
using IOCX.Application.Providers;
using IOCX.Domain;
using IOCX.Infrastructure.Security;

namespace IOCX.Wpf.ViewModels;

/// <summary>
/// Backs the settings screen. Provider enablement and credentials, caching, network
/// behaviour, and risk-scoring thresholds.
/// </summary>
public sealed class SettingsViewModel : INotifyPropertyChanged
{
    private readonly IocxOptions _options;
    private readonly IUserSettingsStore _settingsStore;
    private readonly ISecretStore _secretStore;
    private readonly ProviderRegistryFactory _registryFactory;

    private string _statusMessage = string.Empty;
    private bool _hasUnsavedChanges;

    public SettingsViewModel(
        IocxOptions options,
        IUserSettingsStore settingsStore,
        ISecretStore secretStore,
        ProviderRegistryFactory registryFactory)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _settingsStore = settingsStore ?? throw new ArgumentNullException(nameof(settingsStore));
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _registryFactory = registryFactory ?? throw new ArgumentNullException(nameof(registryFactory));

        SaveCommand = new RelayCommand(_ => Save());
        ReloadCommand = new RelayCommand(_ => Reload());

        Providers = new ObservableCollection<ProviderSettingsItem>();
        Reload();
    }

    public ObservableCollection<ProviderSettingsItem> Providers { get; }

    public string SettingsFilePath => _settingsStore.FilePath;

    public bool CacheEnabled
    {
        get => _options.Cache.Enabled;
        set { _options.Cache.Enabled = value; MarkDirty(); OnPropertyChanged(); }
    }

    public int CacheTtlMinutes
    {
        get => _options.Cache.DefaultTtlMinutes;
        set { _options.Cache.DefaultTtlMinutes = Math.Max(0, value); MarkDirty(); OnPropertyChanged(); }
    }

    public int TimeoutSeconds
    {
        get => _options.Network.TimeoutSeconds;
        set { _options.Network.TimeoutSeconds = Math.Clamp(value, 1, 300); MarkDirty(); OnPropertyChanged(); }
    }

    public int MaxConcurrency
    {
        get => _options.Network.MaxConcurrency;
        set { _options.Network.MaxConcurrency = Math.Clamp(value, 1, 32); MarkDirty(); OnPropertyChanged(); }
    }

    public int MediumThreshold
    {
        get => _options.Scoring.MediumThreshold;
        set { _options.Scoring.MediumThreshold = Math.Clamp(value, 0, 100); MarkDirty(); OnPropertyChanged(); }
    }

    public int HighThreshold
    {
        get => _options.Scoring.HighThreshold;
        set { _options.Scoring.HighThreshold = Math.Clamp(value, 0, 100); MarkDirty(); OnPropertyChanged(); }
    }

    public int CriticalThreshold
    {
        get => _options.Scoring.CriticalThreshold;
        set { _options.Scoring.CriticalThreshold = Math.Clamp(value, 0, 100); MarkDirty(); OnPropertyChanged(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set { _statusMessage = value; OnPropertyChanged(); }
    }

    public bool HasUnsavedChanges
    {
        get => _hasUnsavedChanges;
        private set { _hasUnsavedChanges = value; OnPropertyChanged(); }
    }

    /// <summary>
    /// Gets the standing privacy notice. Analysts must be able to see, without digging, that
    /// running an investigation discloses the indicator to every enabled third party.
    /// </summary>
    public string PrivacyNotice =>
        "IOC-X is local-first: indicators stay on this machine until you analyse them. " +
        "Running an investigation sends the indicator to every enabled provider below, which " +
        "discloses it to that third party and may be logged or retained by them. Disable any " +
        "provider you do not want to receive your indicators.";

    public ICommand SaveCommand { get; }

    public ICommand ReloadCommand { get; }

    /// <summary>Rebuilds the provider rows from the catalog and current credential state.</summary>
    public void Reload()
    {
        Providers.Clear();

        foreach (var availability in _registryFactory.DescribeAvailability(_options))
        {
            Providers.Add(new ProviderSettingsItem(
                availability,
                _options.ForProvider(availability.Descriptor.Name),
                _secretStore,
                MarkDirty));
        }

        HasUnsavedChanges = false;
        StatusMessage = $"Loaded settings from {_settingsStore.FilePath}";
        OnPropertyChanged(nameof(CacheEnabled));
        OnPropertyChanged(nameof(CacheTtlMinutes));
        OnPropertyChanged(nameof(TimeoutSeconds));
        OnPropertyChanged(nameof(MaxConcurrency));
        OnPropertyChanged(nameof(MediumThreshold));
        OnPropertyChanged(nameof(HighThreshold));
        OnPropertyChanged(nameof(CriticalThreshold));
    }

    private void Save()
    {
        try
        {
            // Fold each row's enabled flag back into the options graph before persisting.
            foreach (var item in Providers)
            {
                _options.Providers[item.Name] = item.ToOptions();
            }

            _settingsStore.Save(_options);
            HasUnsavedChanges = false;
            StatusMessage =
                $"Saved to {_settingsStore.FilePath}. Provider changes take effect when IOC-X restarts.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not save settings: {ex.Message}";
        }
    }

    private void MarkDirty() => HasUnsavedChanges = true;

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>One provider's row on the settings screen.</summary>
public sealed class ProviderSettingsItem : INotifyPropertyChanged
{
    private readonly ProviderDescriptor _descriptor;
    private readonly ProviderOptions _options;
    private readonly ISecretStore _secretStore;
    private readonly Action _markDirty;

    private bool _enabled;
    private string _keyStatus = string.Empty;

    internal ProviderSettingsItem(
        ProviderAvailability availability,
        ProviderOptions options,
        ISecretStore secretStore,
        Action markDirty)
    {
        _descriptor = availability.Descriptor;
        _options = options;
        _secretStore = secretStore;
        _markDirty = markDirty;
        _enabled = availability.IsEnabled;

        ClearKeyCommand = new RelayCommand(_ => ClearKey(), _ => CanEditKey && HasKey);
        RefreshKeyStatus();
    }

    public string Name => _descriptor.Name;

    public string Description => _descriptor.Description;

    public string SupportedTypes => string.Join(", ", _descriptor.SupportedTypes);

    public string DocumentationUrl => _descriptor.DocumentationUrl;

    public string RateLimit =>
        $"{(_options.RequestsPerWindow > 0 ? _options.RequestsPerWindow : _descriptor.DefaultRequestsPerWindow)} " +
        $"req / {(_options.WindowSeconds > 0 ? _options.WindowSeconds : _descriptor.DefaultWindowSeconds)}s";

    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (_enabled == value) return;
            _enabled = value;
            _markDirty();
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusText));
        }
    }

    public bool RequiresApiKey => _descriptor.RequiresApiKey;

    public bool HasKey => !_descriptor.RequiresApiKey || _secretStore.Has(KeyName);

    /// <summary>
    /// Gets a value indicating whether the key can be edited here. Keys supplied by an
    /// environment variable are owned by the environment, not by the application.
    /// </summary>
    public bool CanEditKey =>
        _descriptor.RequiresApiKey
        && _secretStore.IsWritable
        && !IsSuppliedByEnvironment;

    public bool IsSuppliedByEnvironment =>
        _descriptor.RequiresApiKey
        && _secretStore is CompositeSecretStore composite
        && composite.IsSuppliedByEnvironment(KeyName);

    /// <summary>Gets a description of the credential state. Never contains the key itself.</summary>
    public string KeyStatus
    {
        get => _keyStatus;
        private set { _keyStatus = value; OnPropertyChanged(); }
    }

    public string KeyName => _options.ApiKeyEnvironmentVariable ?? _descriptor.ApiKeyEnvironmentVariable ?? string.Empty;

    public string StatusText
    {
        get
        {
            if (!Enabled) return "Disabled";
            return HasKey ? "Active" : "Not configured";
        }
    }

    public ICommand ClearKeyCommand { get; }

    /// <summary>
    /// Stores a new API key for this provider. Called from the view's password box, which is
    /// the only place a key value is ever handled.
    /// </summary>
    public void SetKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key) || !CanEditKey)
        {
            return;
        }

        _secretStore.Set(KeyName, key.Trim());
        RefreshKeyStatus();
    }

    private void ClearKey()
    {
        if (!CanEditKey)
        {
            return;
        }

        _secretStore.Delete(KeyName);
        RefreshKeyStatus();
    }

    private void RefreshKeyStatus()
    {
        KeyStatus = !_descriptor.RequiresApiKey
            ? "No credentials required"
            : IsSuppliedByEnvironment
                ? $"Supplied by {KeyName} environment variable"
                : HasKey
                    ? "Stored locally, encrypted"
                    : $"Not set. Provide a key below or set {KeyName}.";

        OnPropertyChanged(nameof(HasKey));
        OnPropertyChanged(nameof(CanEditKey));
        OnPropertyChanged(nameof(StatusText));
    }

    internal ProviderOptions ToOptions()
    {
        _options.Enabled = Enabled;
        return _options;
    }

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
