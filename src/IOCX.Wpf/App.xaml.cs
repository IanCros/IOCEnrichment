using IOCX.Wpf.Services;
using IOCX.Wpf.ViewModels;
using IOCX.Wpf.Views;
using IOCX.Application;
using IOCX.Application.Configuration;
using IOCX.Application.Providers;
using IOCX.Domain;
using IOCX.Infrastructure;
using IOCX.Infrastructure.Configuration;
using IOCX.Infrastructure.Repositories;
using IOCX.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Windows;

namespace IOCX.Wpf;

public partial class App : System.Windows.Application
{
    private readonly IServiceProvider _serviceProvider;

    public App()
    {
        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();
    }

    private void ConfigureServices(IServiceCollection services)
    {
        // Settings are layered. The copy shipped beside the executable provides defaults, the
        // per-user file overrides it, and environment variables win over both. Base path is the
        // install directory so configuration is found regardless of the working directory.
        var userSettingsStore = new JsonUserSettingsStore();

        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
            .AddJsonFile(userSettingsStore.FilePath, optional: true, reloadOnChange: false)
            .AddEnvironmentVariables("IOCX_")
            .Build();

        var options = new IocxOptions();
        configuration.Bind(options);

        services.AddSingleton<IUserSettingsStore>(userSettingsStore);

        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton(options);
        services.AddSingleton(options.Network);
        services.AddSingleton(options.Cache);
        services.AddSingleton(options.Scoring);
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlite("Data Source=iocx.db"),
            ServiceLifetime.Singleton);

        // Core application services
        services.AddSingleton<IIocClassifier, IocClassifier>();
        services.AddSingleton<IIocNormalizer, IocNormalizer>();
        services.AddSingleton<IIocFactory, IocFactory>();
        services.AddSingleton<IEnrichmentService, EnrichmentService>();
        services.AddSingleton<IHttpClient, HttpClientWrapper>();
        services.AddSingleton<IRiskScoringService, RiskScoringService>();
        services.AddSingleton<IConfidenceScoringService, ConfidenceScoringService>();
        services.AddSingleton<IIocCorrelationService, IocCorrelationService>();
        services.AddSingleton<IInvestigationSummaryService, InvestigationSummaryService>();
        services.AddSingleton<IInvestigationAnalysisService, InvestigationAnalysisService>();

        // Enrich, analyse, and persist as one operation, so every investigation run from the
        // UI lands in history rather than existing only on screen.
        services.AddSingleton<IInvestigationRecorder, InvestigationRecorder>();
        services.AddSingleton<IInvestigationService, InvestigationService>();
        services.AddSingleton<IInvestigationHistoryService, InvestigationHistoryService>();

        // Confirms destructive actions. Abstracted so view models never call MessageBox.
        services.AddSingleton<IUserPrompt, MessageBoxUserPrompt>();

        // API keys come from the environment first, then from DPAPI-encrypted local storage.
        // Nothing else in the application reads credentials directly.
        services.AddSingleton<ISecretStore>(_ => SecretStoreFactory.Create());
        services.AddSingleton<IDnsResolver, SystemNetDnsResolver>();
        services.AddSingleton<ProviderRegistryFactory>();

        // The registry contains only providers that are enabled and credentialed, so the
        // enrichment core never has to reason about configuration or missing keys.
        services.AddSingleton<IProviderRegistry>(sp =>
            sp.GetRequiredService<ProviderRegistryFactory>()
              .Create(sp.GetRequiredService<IocxOptions>()));

        // ViewModels
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<InvestigationViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<SettingsViewModel>();

        // Views
        services.AddTransient<IOCX.Wpf.Views.DashboardView>();
        services.AddTransient<IOCX.Wpf.Views.InvestigationView>();
        services.AddTransient<IOCX.Wpf.Views.HistoryView>();
        services.AddTransient<IOCX.Wpf.Views.SettingsView>();
        services.AddTransient<MainWindow>();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var dbContext = _serviceProvider.GetRequiredService<AppDbContext>();
        dbContext.Database.Migrate();
        var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    public IServiceProvider GetServiceProvider() => _serviceProvider;
}
