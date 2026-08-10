namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>VirusTotal threat intelligence provider.</summary>
public sealed class VirusTotalProvider : IEnrichmentProvider
{
    private readonly IHttpClient _httpClient;
    private readonly IRateLimiter _rateLimiter;
    private readonly string _apiKey;

    public VirusTotalProvider(IHttpClient httpClient, IRateLimiter rateLimiter, string apiKey)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
    }

    /// <inheritdoc />
    public string Name => "VirusTotal";

    /// <inheritdoc />
    public bool Supports(Ioc ioc)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        return ioc.Type is IocType.IPv4 or IocType.IPv6 or IocType.Domain or IocType.Url or IocType.Md5 or IocType.Sha1 or IocType.Sha256;
    }

    /// <inheritdoc />
    public async Task<ProviderResult> EnrichAsync(Ioc ioc, CancellationToken cancellationToken = default)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);

            var url = BuildUrl(ioc);
            var startTime = DateTimeOffset.UtcNow;

            // VirusTotal authenticates with the x-apikey header on every request.
            var headers = new Dictionary<string, string>
            {
                ["x-apikey"] = _apiKey,
                ["Accept"] = "application/json"
            };

            var response = await _httpClient.GetAsync(url, headers, cancellationToken);
            var duration = (long)(DateTimeOffset.UtcNow - startTime).TotalMilliseconds;

            return response.StatusCode switch
            {
                System.Net.HttpStatusCode.OK => ProcessSuccessResponse(response.Content!, ioc, duration),
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
                    ErrorMessage = "IOC not found in VirusTotal database."
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

    private string BuildUrl(Ioc ioc)
    {
        return ioc.Type switch
        {
            IocType.IPv4 or IocType.IPv6 => $"https://www.virustotal.com/api/v3/ip_addresses/{ioc.NormalizedValue}",
            IocType.Domain => $"https://www.virustotal.com/api/v3/domains/{ioc.NormalizedValue}",
            IocType.Url => $"https://www.virustotal.com/api/v3/urls/{Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(ioc.NormalizedValue)).TrimEnd('=')}",
            IocType.Md5 or IocType.Sha1 or IocType.Sha256 => $"https://www.virustotal.com/api/v3/files/{ioc.NormalizedValue}",
            _ => throw new NotSupportedException($"IOC type {ioc.Type} is not supported by VirusTotal.")
        };
    }

    private ProviderResult ProcessSuccessResponse(string content, Ioc ioc, long duration)
    {
        try
        {
            var data = System.Text.Json.JsonDocument.Parse(content);
            var attributes = data.RootElement.GetProperty("data").GetProperty("attributes");
            var stats = attributes.GetProperty("last_analysis_stats");
            var malicious = stats.GetProperty("malicious").GetInt32();
            var suspicious = stats.GetProperty("suspicious").GetInt32();
            var harmless = stats.GetProperty("harmless").GetInt32();
            var undetected = stats.GetProperty("undetected").GetInt32();

            var reputation = attributes.TryGetProperty("reputation", out var rep) ? rep.GetInt32() : (int?)null;

            var normalizedData = $"Malicious: {malicious}\nSuspicious: {suspicious}\nHarmless: {harmless}\nUndetected: {undetected}";
            if (reputation.HasValue)
            {
                normalizedData += $"\nReputation: {reputation.Value}";
            }

            var lastAnalysis = attributes.TryGetProperty("last_analysis_date", out var analysed)
                && analysed.TryGetInt64(out var epochSeconds)
                    ? DateTimeOffset.FromUnixTimeSeconds(epochSeconds)
                    : (DateTimeOffset?)null;

            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                Duration = duration,
                NormalizedData = normalizedData,
                Findings = new ProviderFindings
                {
                    Detections = new DetectionFacts(malicious, suspicious, harmless, undetected, reputation),
                    LastActivityAt = lastAnalysis
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
                ErrorMessage = "Failed to parse VirusTotal response."
            };
        }
    }
}
