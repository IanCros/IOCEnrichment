namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>AbuseIPDB threat intelligence provider.</summary>
public sealed class AbuseIpDbProvider : IEnrichmentProvider
{
    private readonly IHttpClient _httpClient;
    private readonly IRateLimiter _rateLimiter;
    private readonly string _apiKey;

    public AbuseIpDbProvider(IHttpClient httpClient, IRateLimiter rateLimiter, string apiKey)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
    }

    /// <inheritdoc />
    public string Name => "AbuseIPDB";

    /// <inheritdoc />
    public bool Supports(Ioc ioc)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        return ioc.Type is IocType.IPv4 or IocType.IPv6;
    }

    /// <inheritdoc />
    public async Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        if (!Supports(ioc))
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Unsupported,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = $"IOC type {ioc.Type} is not supported by AbuseIPDB."
            };
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);

            var url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ioc.NormalizedValue)}&maxAgeInDays=90";
            var startTime = DateTimeOffset.UtcNow;

            // AbuseIPDB authenticates with the Key header.
            var headers = new Dictionary<string, string>
            {
                ["Key"] = _apiKey,
                ["Accept"] = "application/json"
            };

            var response = await _httpClient.GetAsync(url, headers, cancellationToken);
            var duration = (long)(DateTimeOffset.UtcNow - startTime).TotalMilliseconds;

            return response.StatusCode switch
            {
                System.Net.HttpStatusCode.OK => ProcessSuccessResponse(response.Content!, duration),
                System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden => new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Unauthorized,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = "Invalid API key or insufficient permissions."
                },
                System.Net.HttpStatusCode.NotFound => new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Unavailable,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = "IP address not found in AbuseIPDB database."
                },
                System.Net.HttpStatusCode.TooManyRequests => new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.RateLimited,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = "Rate limit exceeded."
                },
                _ when ((int)response.StatusCode >= 500) => new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Unavailable,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = $"Server error: {(int)response.StatusCode}"
                },
                _ => new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Error,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = $"HTTP {(int)response.StatusCode}: {response.ErrorMessage}"
                }
            };
        }
        catch (OperationCanceledException)
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Timeout,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = "Request timed out or was canceled."
            };
        }
        catch (Exception ex)
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Error,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = $"Error: {ex.Message}"
            };
        }
    }

    private ProviderResult ProcessSuccessResponse(string content, long duration)
    {
        try
        {
            var data = System.Text.Json.JsonDocument.Parse(content);
            var result = data.RootElement.GetProperty("data");

            var abuseScore = result.GetProperty("abuseConfidenceScore").GetInt32();
            var country = result.GetProperty("countryCode").GetString();
            var isp = result.GetProperty("isp").GetString();
            var domain = result.GetProperty("domain").GetString();
            var isPublic = result.GetProperty("isPublic").GetBoolean();
            var isTor = result.GetProperty("isTor").GetBoolean();
            var asn = result.TryGetProperty("asn", out var asnProp) ? asnProp.GetInt32() : (int?)null;
            var asnOrg = result.TryGetProperty("asnOrg", out var asnOrgProp) ? asnOrgProp.GetString() : null;

            var normalizedData = $"Abuse Confidence: {abuseScore}%\nCountry: {country}\nISP: {isp}\nDomain: {domain}\nPublic: {isPublic}\nTOR: {isTor}";
            if (asn.HasValue && !string.IsNullOrEmpty(asnOrg))
            {
                normalizedData += $"\nASN: AS{asn.Value} ({asnOrg})";
            }

            var totalReports = result.TryGetProperty("totalReports", out var reportsProp)
                ? reportsProp.GetInt32()
                : (int?)null;
            var usageType = result.TryGetProperty("usageType", out var usageProp) ? usageProp.GetString() : null;
            var lastReportedAt = result.TryGetProperty("lastReportedAt", out var lastProp)
                && DateTimeOffset.TryParse(lastProp.GetString(), out var parsedLastReported)
                    ? parsedLastReported
                    : (DateTimeOffset?)null;

            var related = new List<RelatedIndicator>();
            if (!string.IsNullOrWhiteSpace(domain))
            {
                related.Add(new RelatedIndicator(domain, IocType.Domain, RelationshipType.RelatedTo, 60));
            }

            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                Duration = duration,
                NormalizedData = normalizedData,
                Findings = new ProviderFindings
                {
                    Abuse = new AbuseFacts(abuseScore, totalReports, lastReportedAt, usageType),
                    Infrastructure = new InfrastructureFacts(
                        Organization: asnOrg ?? isp,
                        Asn: asn.HasValue ? $"AS{asn.Value}" : null,
                        CountryCode: country),
                    Related = related,
                    LastActivityAt = lastReportedAt
                }
            };
        }
        catch
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.InvalidResponse,
                Timestamp = DateTimeOffset.UtcNow,
                Duration = duration,
                ErrorMessage = "Failed to parse AbuseIPDB response."
            };
        }
    }
}
