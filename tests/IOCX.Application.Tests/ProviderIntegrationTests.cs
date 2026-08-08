namespace IOCX.Application.Tests;

using IOCX.Application;
using IOCX.Application.Providers;
using IOCX.Domain;
using System.Net;

/// <summary>Tests for the three threat intelligence providers using mocked HTTP responses.</summary>
public class ProviderIntegrationTests
{
    private static Ioc CreateIoc(string value, IocType type) => new(value, value, type);

    private static MockHttpClient CreateMockClient(HttpStatusCode status, string content)
        => new(status, content);

    private static IRateLimiter CreateNoOpRateLimiter() => new NoOpRateLimiter();

    [Fact]
    public async Task VirusTotal_ValidIpResponse_ReturnsSuccessWithStats()
    {
        // Arrange
        var json = """
        {
          "data": {
            "attributes": {
              "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 3,
                "harmless": 65,
                "undetected": 20
              },
              "reputation": -45
            }
          }
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Equal("VirusTotal", result.ProviderName);
        Assert.Contains("Malicious: 12", result.NormalizedData);
        Assert.Contains("Suspicious: 3", result.NormalizedData);
        Assert.Contains("Harmless: 65", result.NormalizedData);
        Assert.Contains("Undetected: 20", result.NormalizedData);
        Assert.Contains("Reputation: -45", result.NormalizedData);
    }

    [Fact]
    public async Task VirusTotal_ValidDomainResponse_ReturnsSuccess()
    {
        // Arrange
        var json = """
        {
          "data": {
            "attributes": {
              "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 1,
                "harmless": 80,
                "undetected": 14
              },
              "reputation": -10
            }
          }
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Malicious: 5", result.NormalizedData);
    }

    [Fact]
    public async Task VirusTotal_ValidUrlResponse_ReturnsSuccess()
    {
        // Arrange
        var json = """
        {
          "data": {
            "attributes": {
              "last_analysis_stats": {
                "malicious": 8,
                "suspicious": 2,
                "harmless": 40,
                "undetected": 50
              },
              "reputation": -20
            }
          }
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("https://example.com/test", IocType.Url);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Malicious: 8", result.NormalizedData);
    }

    [Fact]
    public async Task VirusTotal_ValidHashResponse_ReturnsSuccess()
    {
        // Arrange
        var json = """
        {
          "data": {
            "attributes": {
              "last_analysis_stats": {
                "malicious": 20,
                "suspicious": 5,
                "harmless": 30,
                "undetected": 45
              },
              "reputation": -60
            }
          }
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("d41d8cd98f00b204e9800998ecf8427e", IocType.Md5);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Malicious: 20", result.NormalizedData);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task VirusTotal_Unauthorized_ReturnsUnauthorized(HttpStatusCode status)
    {
        // Arrange
        var client = CreateMockClient(status, "{}");
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task VirusTotal_NotFound_ReturnsUnavailable()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.NotFound, "{}");
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unavailable, result.Status);
    }

    [Fact]
    public async Task VirusTotal_RateLimited_ReturnsRateLimited()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.TooManyRequests, "{}");
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.RateLimited, result.Status);
    }

    [Fact]
    public async Task VirusTotal_ServerError_ReturnsUnavailable()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.InternalServerError, "{}");
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unavailable, result.Status);
    }

    [Fact]
    public async Task VirusTotal_MalformedJson_ReturnsInvalidResponse()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.OK, "not json");
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    [Fact]
    public async Task VirusTotal_MissingFields_ReturnsInvalidResponse()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.OK, "{\"data\":{\"attributes\":{}}}");
        var provider = new VirusTotalProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    [Fact]
    public void VirusTotal_UnsupportedType_ReturnsFalse()
    {
        // Arrange
        var provider = new VirusTotalProvider(CreateMockClient(HttpStatusCode.OK, "{}"), CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("user@example.com", IocType.Email);

        // Act
        var supports = provider.Supports(ioc);

        // Assert
        Assert.False(supports);
    }

    [Fact]
    public async Task AbuseIpDb_ValidIpv4Response_ReturnsSuccess()
    {
        // Arrange
        var json = """
        {
          "data": {
            "abuseConfidenceScore": 85,
            "countryCode": "US",
            "isp": "Example ISP",
            "domain": "example.com",
            "isPublic": true,
            "isTor": false,
            "asn": 12345,
            "asnOrg": "Example ASN Org"
          }
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Abuse Confidence: 85", result.NormalizedData);
        Assert.Contains("Country: US", result.NormalizedData);
        Assert.Contains("ASN: AS12345", result.NormalizedData);
    }

    [Fact]
    public async Task AbuseIpDb_ValidIpv6Response_ReturnsSuccess()
    {
        // Arrange
        var json = """
        {
          "data": {
            "abuseConfidenceScore": 50,
            "countryCode": "DE",
            "isp": "Example ISP",
            "domain": "example.de",
            "isPublic": true,
            "isTor": true,
            "asn": 54321,
            "asnOrg": "Example ASN Org"
          }
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("2001:db8::1", IocType.IPv6);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Abuse Confidence: 50", result.NormalizedData);
        Assert.Contains("TOR: True", result.NormalizedData);
    }

    [Fact]
    public async Task AbuseIpDb_UnsupportedIoc_ReturnsUnsupported()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.OK, "{}");
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unsupported, result.Status);
    }

    [Fact]
    public async Task AbuseIpDb_Unauthorized_ReturnsUnauthorized()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.Unauthorized, "{}");
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unauthorized, result.Status);
    }

    [Fact]
    public async Task AbuseIpDb_RateLimited_ReturnsRateLimited()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.TooManyRequests, "{}");
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.RateLimited, result.Status);
    }

    [Fact]
    public async Task AbuseIpDb_ServerError_ReturnsUnavailable()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.InternalServerError, "{}");
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unavailable, result.Status);
    }

    [Fact]
    public async Task AbuseIpDb_MalformedJson_ReturnsInvalidResponse()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.OK, "not json");
        var provider = new AbuseIpDbProvider(client, CreateNoOpRateLimiter(), "test-key");
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    [Fact]
    public async Task ThreatFox_SuccessfulMatch_ReturnsSuccess()
    {
        // Arrange
        var json = """
        {
          "query_status": "ok",
          "data": [
            {
              "ioc": "example.com",
              "ioc_type": "domain",
              "malware": "ExampleMalware",
              "confidence_level": 90,
              "first_seen": "2024-01-01",
              "last_seen": "2024-06-01"
            }
          ]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Matches: 1", result.NormalizedData);
        Assert.Contains("Malware: ExampleMalware", result.NormalizedData);
        Assert.Contains("Confidence: 90", result.NormalizedData);
    }

    [Fact]
    public async Task ThreatFox_MultipleMatches_ReturnsAllMatches()
    {
        // Arrange
        var json = """
        {
          "query_status": "ok",
          "data": [
            {
              "ioc": "example.com",
              "ioc_type": "domain",
              "malware": "MalwareA",
              "confidence_level": 90,
              "first_seen": "2024-01-01",
              "last_seen": "2024-06-01"
            },
            {
              "ioc": "example.com",
              "ioc_type": "domain",
              "malware": "MalwareB",
              "confidence_level": 75,
              "first_seen": "2024-02-01",
              "last_seen": "2024-05-01"
            },
            {
              "ioc": "example.com",
              "ioc_type": "domain",
              "malware": "MalwareC",
              "confidence_level": 60,
              "first_seen": "2024-03-01",
              "last_seen": "2024-04-01"
            }
          ]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Matches: 3", result.NormalizedData);
        Assert.Contains("Malware: MalwareA", result.NormalizedData);
        Assert.Contains("Malware: MalwareB", result.NormalizedData);
        Assert.Contains("Malware: MalwareC", result.NormalizedData);
    }

    [Fact]
    public async Task ThreatFox_NoMatches_ReturnsSuccessWithNoMatches()
    {
        // Arrange
        var json = """{"query_status": "no_result"}""";
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("No ThreatFox matches found", result.NormalizedData);
    }

    [Fact]
    public async Task ThreatFox_UnsupportedIoc_ReturnsUnsupported()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.OK, "{}");
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("user@example.com", IocType.Email);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Unsupported, result.Status);
    }

    [Fact]
    public async Task ThreatFox_ApiError_ReturnsError()
    {
        // Arrange
        var json = """{"query_status": "invalid_request"}""";
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Error, result.Status);
    }

    [Fact]
    public async Task ThreatFox_MalformedResponse_ReturnsInvalidResponse()
    {
        // Arrange
        var client = CreateMockClient(HttpStatusCode.OK, "not json");
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.InvalidResponse, result.Status);
    }

    [Fact]
    public async Task ThreatFox_MissingFields_ReturnsSuccessWithDefaults()
    {
        // Arrange
        var json = """
        {
          "query_status": "ok",
          "data": [
            {
              "ioc": "example.com"
            }
          ]
        }
        """;
        var client = CreateMockClient(HttpStatusCode.OK, json);
        var provider = new ThreatFoxProvider(client, CreateNoOpRateLimiter());
        var ioc = CreateIoc("example.com", IocType.Domain);

        // Act
        var result = await provider.EnrichAsync(ioc);

        // Assert
        Assert.Equal(ProviderStatus.Success, result.Status);
        Assert.Contains("Malware: Unknown", result.NormalizedData);
    }

    [Fact]
    public async Task ProviderIsolation_OneFails_OthersStillReturn()
    {
        // Arrange
        var registry = new ProviderRegistry();
        var vtClient = CreateMockClient(HttpStatusCode.OK, """
        {
          "data": {
            "attributes": {
              "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 0,
                "harmless": 10,
                "undetected": 5
              }
            }
          }
        }
        """);
        var abuseClient = CreateMockClient(HttpStatusCode.TooManyRequests, "{}");
        var tfClient = CreateMockClient(HttpStatusCode.OK, """{"query_status": "no_result"}""");

        registry.Register(new VirusTotalProvider(vtClient, CreateNoOpRateLimiter(), "test-key"));
        registry.Register(new AbuseIpDbProvider(abuseClient, CreateNoOpRateLimiter(), "test-key"));
        registry.Register(new ThreatFoxProvider(tfClient, CreateNoOpRateLimiter()));

        var service = new EnrichmentService(registry, new NetworkOptions { MaxConcurrency = 3 });
        var ioc = CreateIoc("192.0.2.1", IocType.IPv4);

        // Act
        var results = await service.EnrichAsync(ioc);

        // Assert
        Assert.Equal(3, results.Count);
        Assert.Contains(results, r => r.ProviderName == "VirusTotal" && r.Status == ProviderStatus.Success);
        Assert.Contains(results, r => r.ProviderName == "AbuseIPDB" && r.Status == ProviderStatus.RateLimited);
        Assert.Contains(results, r => r.ProviderName == "ThreatFox" && r.Status == ProviderStatus.Success);
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

        public Task<HttpResponseResult> GetAsync(string url, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new HttpResponseResult
            {
                StatusCode = _status,
                Content = _content,
                ErrorMessage = _status == HttpStatusCode.OK ? null : $"HTTP {(int)_status}"
            });
        }

        public Task<HttpResponseResult> PostAsync(string url, string? content = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new HttpResponseResult
            {
                StatusCode = _status,
                Content = _content,
                ErrorMessage = _status == HttpStatusCode.OK ? null : $"HTTP {(int)_status}"
            });
        }

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
