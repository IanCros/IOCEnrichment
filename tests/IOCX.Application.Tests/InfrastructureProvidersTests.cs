namespace IOCX.Application.Tests;

using IOCX.Application;
using IOCX.Application.Providers;
using IOCX.Domain;
using System.Net;

/// <summary>Tests for Shodan, URLhaus, DNS, and RDAP providers using mocked HTTP responses.</summary>
public class InfrastructureProvidersTests
{
    private static Ioc CreateIoc(string value, IocType type) => new(value, value, type);
    private static MockHttpClient CreateMockClient(HttpStatusCode status, string content) => new(status, content);
    private static IRateLimiter CreateNoOpRateLimiter() => new NoOpRateLimiter();

    // --- Shodan tests ---

    [Fact]
    public async Task Shodan_ValidIpResponse_ReturnsSuccess()
    {
        var json = """
        {
          "ip_str": "192.0.2.1",
          "org": "Example Org",
          "isp": "Example ISP",
          "asn": "AS12345",
          "country_name": "United States",
          "city": "Testville",
          "region_name": "Test Region",
          "hostnames": ["test.example.com"],
          "domains": ["example.com"],
          "ports": [22, 80, 443],
          "last_update": "2024-01-01T00:00:00Z",
          "data": [
            {"port": 22, "product": "OpenSSH", "version": "9.0"},
            {"port": 80, "product": "Apache", "version": "2.4.57"},
            {"port": 443, "product": "nginx", "version": "1.24.0"}
          ]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Equal("Shodan", result.ProviderName);
        Assert.Contains("Organization: Example Org", result.NormalizedData);
        Assert.Contains("ASN: AS12345", result.NormalizedData);
        Assert.Contains("Port 22", result.NormalizedData);
        Assert.Contains("Port 443", result.NormalizedData);
    }

    [Fact]
    public async Task Shodan_MultiService_ReturnsAllServices()
    {
        var json = """
        {
          "ip_str": "192.0.2.5",
          "data": [
            {"port": 80, "product": "Apache", "version": "2.4"},
            {"port": 443, "product": "nginx", "version": "1.20"}
          ]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.5", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Services:", result.NormalizedData);
        Assert.Contains("Port 80", result.NormalizedData);
        Assert.Contains("Port 443", result.NormalizedData);
    }

    [Fact]
    public async Task Shodan_MissingFields_ReturnsPartialData()
    {
        var json = """{"ip_str": "192.0.2.9"}""";
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.9", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("IP: 192.0.2.9", result.NormalizedData);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task Shodan_AuthErrors_ReturnsUnauthorized(HttpStatusCode status)
    {
        var client = CreateMockClient(status, "{}");
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task Shodan_NotFound_ReturnsUnavailable()
    {
        var client = CreateMockClient(HttpStatusCode.NotFound, "{}");
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unavailable, result.Status);
    }

    [Fact]
    public async Task Shodan_RateLimited_ReturnsRateLimited()
    {
        var client = CreateMockClient(HttpStatusCode.TooManyRequests, "{}");
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.RateLimited, result.Status);
    }

    [Fact]
    public async Task Shodan_ServerError_ReturnsUnavailable()
    {
        var client = CreateMockClient(HttpStatusCode.InternalServerError, "{}");
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unavailable, result.Status);
    }

    [Fact]
    public async Task Shodan_MalformedJson_ReturnsInvalidResponse()
    {
        var client = CreateMockClient(HttpStatusCode.OK, "not-json");
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    [Fact]
    public async Task Shodan_UnsupportedIoc_ReturnsUnsupported()
    {
        var client = CreateMockClient(HttpStatusCode.OK, "{}");
        var provider = new ShodanProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unsupported, result.Status);
    }

    // --- URLhaus tests ---

    [Fact]
    public async Task Urlhaus_UrlMatch_ReturnsSuccess()
    {
        var json = """
        {
          "query_status": "ok",
          "url": "https://example.com/malware.exe",
          "url_status": "offline",
          "threat": "malware_download",
          "malware": "Trojan.Downloader",
          "host": "example.com",
          "ip_address": "192.0.2.1",
          "date_added": "2024-01-01",
          "last_online": "2024-01-15",
          "reporter": "example_reporter",
          "tags": ["exe", "trojan"]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new UrlhausProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("https://example.com/malware.exe", IocType.Url);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Matches: 1", result.NormalizedData);
        Assert.Contains("URL: https://example.com/malware.exe", result.NormalizedData);
        Assert.Contains("Threat: malware_download", result.NormalizedData);
        Assert.Contains("Malware: Trojan.Downloader", result.NormalizedData);
    }

    [Fact]
    public async Task Urlhaus_DomainMatch_ReturnsSuccess()
    {
        var json = """
        {
          "query_status": "ok",
          "data": [
            {"url": "https://example.com/a", "threat": "malware_download", "malware": "MalwareA"},
            {"url": "https://example.com/b", "threat": "malware_download", "malware": "MalwareB"}
          ]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new UrlhausProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Matches: 2", result.NormalizedData);
        Assert.Contains("Malware: MalwareA", result.NormalizedData);
        Assert.Contains("Malware: MalwareB", result.NormalizedData);
    }

    [Fact]
    public async Task Urlhaus_NoMatches_ReturnsSuccess()
    {
        var json = """{"query_status": "no_results"}""";
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new UrlhausProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("No URLhaus matches found", result.NormalizedData);
    }

    [Fact]
    public async Task Urlhaus_ApiError_ReturnsError()
    {
        var json = """{"query_status": "invalid_url"}""";
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new UrlhausProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Error, result.Status);
    }

    [Fact]
    public async Task Urlhaus_MalformedResponse_ReturnsInvalidResponse()
    {
        var client = CreateMockClient(HttpStatusCode.OK, "not-json");
        var provider = new UrlhausProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    [Fact]
    public async Task Urlhaus_UnsupportedIoc_ReturnsUnsupported()
    {
        var client = CreateMockClient(HttpStatusCode.OK, "{}");
        var provider = new UrlhausProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("user@example.com", IocType.Email);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unsupported, result.Status);
    }

    // --- DNS tests ---

    [Fact]
    public void Dns_SupportsDomain_ReturnsTrue()
    {
        var provider = new DnsProvider(CreateNoOpRateLimiter());
        Assert.True(provider.Supports(CreateIoc("example.com", IocType.Domain)));
    }

    [Fact]
    public void Dns_SupportsIp_ReturnsTrue()
    {
        var provider = new DnsProvider(CreateNoOpRateLimiter());
        Assert.True(provider.Supports(CreateIoc("192.0.2.1", IocType.IPv4)));
    }

    [Fact]
    public void Dns_UnsupportedEmail_ReturnsFalse()
    {
        var provider = new DnsProvider(CreateNoOpRateLimiter());
        Assert.False(provider.Supports(CreateIoc("user@example.com", IocType.Email)));
    }

    [Fact]
    public async Task Dns_UnsupportedIoc_ReturnsUnsupported()
    {
        var provider = new DnsProvider(CreateNoOpRateLimiter());
        var ioc = CreateIoc("user@example.com", IocType.Email);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unsupported, result.Status);
    }

    // --- RDAP tests ---

    [Fact]
    public async Task Rdap_SuccessfulDomainLookup_ReturnsSuccess()
    {
        var json = """
        {
          "handle": "D12345-COM",
          "entities": [
            {
              "roles": ["registrar"],
              "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]
            }
          ],
          "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"}
          ],
          "nameservers": [
            {"ldhName": "ns1.example.com"},
            {"ldhName": "ns2.example.com"}
          ],
          "status": ["clientTransferProhibited", "clientDeleteProhibited"]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new RdapProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Registrar: Example Registrar", result.NormalizedData);
        Assert.Contains("Created: 2020-01-01", result.NormalizedData);
        Assert.Contains("Nameservers:", result.NormalizedData);
        Assert.Contains("ns1.example.com", result.NormalizedData);
        Assert.Contains("clientTransferProhibited", result.NormalizedData);
    }

    [Fact]
    public async Task Rdap_NotFound_ReturnsUnavailable()
    {
        var client = CreateMockClient(HttpStatusCode.NotFound, "{}");
        var provider = new RdapProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("nonexistent-domain.invalid", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unavailable, result.Status);
    }

    [Fact]
    public async Task Rdap_PrivacyRedacted_ReturnsPartialData()
    {
        var json = """
        {
          "handle": "D99999-COM",
          "events": [{"eventAction": "registration", "eventDate": "2022-05-05T00:00:00Z"}]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new RdapProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("privacy-example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Created: 2022-05-05", result.NormalizedData);
    }

    [Fact]
    public async Task Rdap_UnsupportedIoc_ReturnsUnsupported()
    {
        var client = CreateMockClient(HttpStatusCode.OK, "{}");
        var provider = new RdapProvider(client, CreateNoOpRateLimiter());

        // RDAP has no record type for a file hash.
        var ioc = CreateIoc("d41d8cd98f00b204e9800998ecf8427e", IocType.Md5);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.Unsupported, result.Status);
    }

    [Fact]
    public async Task Rdap_IpAddress_QueriesAllocationEndpoint()
    {
        var client = new MockHttpClient(
            HttpStatusCode.OK,
            "{\"handle\":\"NET-192-0-2-0-1\",\"name\":\"TEST-NET-1\",\"country\":\"US\"," +
            "\"startAddress\":\"192.0.2.0\",\"endAddress\":\"192.0.2.255\"}");

        var provider = new RdapProvider(client, CreateNoOpRateLimiter());

        var result = await provider.EnrichAsync(CreateIoc("192.0.2.1", IocType.IPv4));

        Assert.Equal(ProviderStatus.Success, result.Status);

        // Addresses live under /ip/, not /domain/ — querying the wrong path returns 404.
        Assert.Contains("/ip/192.0.2.1", client.LastUrl!, StringComparison.Ordinal);
        Assert.Contains("TEST-NET-1", result.NormalizedData!);
        Assert.Equal("US", result.Findings?.Infrastructure?.CountryCode);
    }

    [Fact]
    public async Task Rdap_Domain_QueriesDomainEndpointAndReportsRegistration()
    {
        var client = new MockHttpClient(
            HttpStatusCode.OK,
            "{\"handle\":\"EXAMPLE-COM\",\"events\":[{\"eventAction\":\"registration\"," +
            "\"eventDate\":\"1995-08-14T04:00:00Z\"}],\"nameservers\":[{\"ldhName\":\"a.iana-servers.net\"}]}");

        var provider = new RdapProvider(client, CreateNoOpRateLimiter());

        var result = await provider.EnrichAsync(CreateIoc("example.com", IocType.Domain));

        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("/domain/example.com", client.LastUrl!, StringComparison.Ordinal);
        Assert.Contains("a.iana-servers.net", result.Findings?.Registration?.Nameservers ?? []);
    }

    [Fact]
    public async Task Rdap_MalformedResponse_ReturnsInvalidResponse()
    {
        var client = CreateMockClient(HttpStatusCode.OK, "not-json");
        var provider = new RdapProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        var result = await provider.EnrichAsync(ioc);

        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    // --- Provider isolation test with all 7 providers (using IPv4) ---

    [Fact]
    public async Task AllProviders_RunConcurrently_IsolationPreserved()
    {
        var registry = new ProviderRegistry();

        registry.Register(new VirusTotalProvider(
            CreateMockClient(HttpStatusCode.OK, """{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"harmless":10,"undetected":5}}}}"""),
            CreateNoOpRateLimiter(), "key"));

        registry.Register(new AbuseIpDbProvider(
            CreateMockClient(HttpStatusCode.OK, """{"data":{"abuseConfidenceScore":20,"countryCode":"US","isp":"ISP","domain":"example.com","isPublic":true,"isTor":false}}"""),
            CreateNoOpRateLimiter(), "key"));

        registry.Register(new ThreatFoxProvider(
            CreateMockClient(HttpStatusCode.OK, """{"query_status":"no_result"}"""),
            CreateNoOpRateLimiter()));

        registry.Register(new ShodanProvider(
            CreateMockClient(HttpStatusCode.TooManyRequests, "{}"),
            CreateNoOpRateLimiter(), "key"));

        registry.Register(new UrlhausProvider(
            CreateMockClient(HttpStatusCode.OK, """{"query_status":"no_results"}"""),
            CreateNoOpRateLimiter()));

        registry.Register(new DnsProvider(CreateNoOpRateLimiter()));

        registry.Register(new RdapProvider(
            CreateMockClient(HttpStatusCode.OK, """{"handle":"D12345"}"""),
            CreateNoOpRateLimiter()));

        var service = new EnrichmentService(registry, new NetworkOptions { MaxConcurrency = 7 });
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        var results = await service.EnrichAsync(ioc);

        // All seven providers answer for an IPv4 address: RDAP serves address allocations
        // from its /ip/ endpoint as well as domain registrations.
        Assert.Equal(7, results.Count);
        Assert.Contains(results, r => r.ProviderName == "VirusTotal" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "AbuseIPDB" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "ThreatFox" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "URLhaus" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "DNS" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "RDAP" && r.Status == ProviderStatus.Success);

        // One provider being rate limited must not disturb the others.
        Assert.Contains(results, r => r.ProviderName == "Shodan" && r.Status == ProviderStatus.RateLimited);
    }

    private sealed class MockHttpClient : IHttpClient
    {
        private readonly HttpStatusCode _status;
        private readonly string _content;

        public MockHttpClient(HttpStatusCode status, string content)
        {
            _status = status;
            _content = content;
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
            ErrorMessage = _status == HttpStatusCode.OK ? null : $"HTTP {(int)_status}"
        };

        public void Dispose() { }
    }

    private sealed class NoOpRateLimiter : IRateLimiter
    {
        public string ProviderName => "NoOp";

        public Task WaitAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}
