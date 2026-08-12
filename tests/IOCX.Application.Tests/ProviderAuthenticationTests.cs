namespace IOCX.Application.Tests;

using System.Net;
using IOCX.Application.Providers;
using IOCX.Domain;

/// <summary>Asserts that each provider actually transmits its credential.</summary>
/// <remarks>
/// Every provider used to accept an API key, store it in a field, and never send it, so
/// authentication failed everywhere. The mock returns 200 whatever headers arrive, so no test
/// that only checked the parsed result could catch it. These check the outgoing request.
/// </remarks>
public class ProviderAuthenticationTests
{
    private const string FakeKey = "not-a-real-key-0000";

    private static Ioc Ip() => new("192.0.2.1", "192.0.2.1", IocType.IPv4);
    private static Ioc Domain() => new("example.com", "example.com", IocType.Domain);
    private static Ioc Url() => new("https://example.com/a", "https://example.com/a", IocType.Url);

    private static IRateLimiter NoLimit() => new PassThroughRateLimiter();

    [Fact]
    public async Task VirusTotal_SendsApiKeyHeader()
    {
        var http = new RecordingHttpClient("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":0,\"suspicious\":0,\"harmless\":1,\"undetected\":0}}}}");

        await new VirusTotalProvider(http, NoLimit(), FakeKey).EnrichAsync(Ip());

        Assert.NotNull(http.LastHeaders);
        Assert.True(http.LastHeaders!.ContainsKey("x-apikey"), "VirusTotal must send the x-apikey header.");
        Assert.Equal(FakeKey, http.LastHeaders["x-apikey"]);
    }

    [Fact]
    public async Task AbuseIpDb_SendsKeyHeader()
    {
        var http = new RecordingHttpClient("{\"data\":{\"abuseConfidenceScore\":0,\"countryCode\":\"US\",\"isp\":\"Example\",\"domain\":\"example.com\",\"isPublic\":true,\"isTor\":false}}");

        await new AbuseIpDbProvider(http, NoLimit(), FakeKey).EnrichAsync(Ip());

        Assert.NotNull(http.LastHeaders);
        Assert.True(http.LastHeaders!.ContainsKey("Key"), "AbuseIPDB must send the Key header.");
        Assert.Equal(FakeKey, http.LastHeaders["Key"]);
    }

    [Fact]
    public async Task Shodan_SendsKeyInQueryString()
    {
        var http = new RecordingHttpClient("{\"ip_str\":\"192.0.2.1\",\"ports\":[]}");

        await new ShodanProvider(http, NoLimit(), FakeKey).EnrichAsync(Ip());

        // Shodan authenticates by query parameter rather than header.
        Assert.NotNull(http.LastUrl);
        Assert.Contains($"key={FakeKey}", http.LastUrl!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThreatFox_SendsAuthKeyHeader()
    {
        var http = new RecordingHttpClient("{\"query_status\":\"no_result\"}");

        await new ThreatFoxProvider(http, NoLimit(), FakeKey).EnrichAsync(Domain());

        Assert.NotNull(http.LastHeaders);
        Assert.True(http.LastHeaders!.ContainsKey("Auth-Key"), "ThreatFox must send the Auth-Key header.");
        Assert.Equal(FakeKey, http.LastHeaders["Auth-Key"]);
    }

    [Fact]
    public async Task Urlhaus_SendsAuthKeyHeader()
    {
        var http = new RecordingHttpClient("{\"query_status\":\"no_results\"}");

        await new UrlhausProvider(http, NoLimit(), FakeKey).EnrichAsync(Url());

        Assert.NotNull(http.LastHeaders);
        Assert.True(http.LastHeaders!.ContainsKey("Auth-Key"), "URLhaus must send the Auth-Key header.");
        Assert.Equal(FakeKey, http.LastHeaders["Auth-Key"]);
    }

    [Fact]
    public async Task ThreatFox_OmitsAuthHeaderWhenNoKeyConfigured()
    {
        var http = new RecordingHttpClient("{\"query_status\":\"no_result\"}");

        await new ThreatFoxProvider(http, NoLimit(), authKey: null).EnrichAsync(Domain());

        // Sending an empty Auth-Key would be worse than sending none. It invites a confusing
        // 401 rather than the provider's documented unauthenticated behaviour.
        Assert.False(http.LastHeaders?.ContainsKey("Auth-Key") ?? false);
    }

    [Fact]
    public async Task Rdap_RequestsRdapMediaType()
    {
        var http = new RecordingHttpClient("{\"objectClassName\":\"domain\"}");

        await new RdapProvider(http, NoLimit()).EnrichAsync(Domain());

        Assert.NotNull(http.LastHeaders);
        Assert.True(http.LastHeaders!.TryGetValue("Accept", out var accept));
        Assert.Contains("application/rdap+json", accept!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Providers_DoNotLeakCredentialsIntoResults()
    {
        var http = new RecordingHttpClient("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":1,\"suspicious\":0,\"harmless\":1,\"undetected\":0}}}}");

        var result = await new VirusTotalProvider(http, NoLimit(), FakeKey).EnrichAsync(Ip());

        Assert.DoesNotContain(FakeKey, result.NormalizedData ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeKey, result.ErrorMessage ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ShodanErrors_DoNotEchoTheKeyBearingUrl()
    {
        var http = new RecordingHttpClient("unauthorized", HttpStatusCode.Unauthorized);

        var result = await new ShodanProvider(http, NoLimit(), FakeKey).EnrichAsync(Ip());

        // Shodan puts its key in the URL, so any message that echoes the URL would leak it.
        Assert.DoesNotContain(FakeKey, result.ErrorMessage ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ShodanTransportErrors_RedactTheKey()
    {
        // Simulates a transport-layer message that does echo the request URL. Error messages
        // are persisted to the investigation record and shown in the UI, so the key must be
        // stripped rather than trusted not to appear.
        // 400 reaches the branch that includes the transport message. The 5xx and auth
        // codes emit fixed text with nothing to redact.
        var http = new RecordingHttpClient(
            content: string.Empty,
            status: HttpStatusCode.BadRequest,
            errorMessage: $"Connection failed for https://api.shodan.io/shodan/host/192.0.2.1?key={FakeKey}");

        var result = await new ShodanProvider(http, NoLimit(), FakeKey).EnrichAsync(Ip());

        Assert.DoesNotContain(FakeKey, result.ErrorMessage ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("[redacted]", result.ErrorMessage!, StringComparison.Ordinal);
    }

    /// <summary>Captures the outgoing request so tests can assert on what was actually sent.</summary>
    private sealed class RecordingHttpClient : IHttpClient
    {
        private readonly string _content;
        private readonly HttpStatusCode _status;
        private readonly string? _errorMessage;

        public RecordingHttpClient(
            string content,
            HttpStatusCode status = HttpStatusCode.OK,
            string? errorMessage = null)
        {
            _content = content;
            _status = status;
            _errorMessage = errorMessage;
        }

        public IReadOnlyDictionary<string, string>? LastHeaders { get; private set; }

        public string? LastUrl { get; private set; }

        public Task<HttpResponseResult> GetAsync(
            string url,
            IReadOnlyDictionary<string, string>? headers = null,
            CancellationToken cancellationToken = default)
        {
            LastUrl = url;
            LastHeaders = headers;
            return Task.FromResult(Respond());
        }

        public Task<HttpResponseResult> PostAsync(
            string url,
            string? content = null,
            IReadOnlyDictionary<string, string>? headers = null,
            CancellationToken cancellationToken = default)
        {
            LastUrl = url;
            LastHeaders = headers;
            return Task.FromResult(Respond());
        }

        private HttpResponseResult Respond() => new()
        {
            StatusCode = _status,
            Content = _content,
            ErrorMessage = _status == HttpStatusCode.OK
                ? null
                : _errorMessage ?? $"HTTP {(int)_status}"
        };

        public void Dispose()
        {
        }
    }

    private sealed class PassThroughRateLimiter : IRateLimiter
    {
        public string ProviderName => "Test";

        public Task WaitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
