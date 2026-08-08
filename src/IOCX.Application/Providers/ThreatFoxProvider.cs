namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>ThreatFox threat intelligence provider.</summary>
public sealed class ThreatFoxProvider : IEnrichmentProvider
{
    private readonly IHttpClient _httpClient;
    private readonly IRateLimiter _rateLimiter;

    public ThreatFoxProvider(IHttpClient httpClient, IRateLimiter rateLimiter)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    }

    /// <inheritdoc />
    public string Name => "ThreatFox";

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

        if (!Supports(ioc))
        {
            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Unsupported,
                Timestamp = DateTimeOffset.UtcNow,
                ErrorMessage = $"IOC type {ioc.Type} is not supported by ThreatFox."
            };
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);

            var url = "https://threatfox-api.abuse.ch/api/v1/";
            var startTime = DateTimeOffset.UtcNow;

            var requestBody = System.Text.Json.JsonSerializer.Serialize(new
            {
                query = "search_ioc",
                search_term = ioc.NormalizedValue
            });

            var response = await _httpClient.PostAsync(url, requestBody, cancellationToken);
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
            var queryStatus = data.RootElement.GetProperty("query_status").GetString();

            if (queryStatus == "no_result")
            {
                return new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Success,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    NormalizedData = "No ThreatFox matches found."
                };
            }

            if (queryStatus != "ok")
            {
                return new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Error,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = $"ThreatFox query status: {queryStatus}"
                };
            }

            var matches = data.RootElement.GetProperty("data");
            var matchCount = matches.GetArrayLength();

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Matches: {matchCount}");

            for (int idx = 0; idx < matchCount; idx++)
            {
                var match = matches[idx];
                var malware = match.TryGetProperty("malware", out var m) ? m.GetString() : "Unknown";
                var confidence = match.TryGetProperty("confidence_level", out var c) ? c.GetInt32() : (int?)null;
                var firstSeen = match.TryGetProperty("first_seen", out var f) ? f.GetString() : null;
                var lastSeen = match.TryGetProperty("last_seen", out var l) ? l.GetString() : null;
                var iocValue = match.TryGetProperty("ioc", out var iocProp) ? iocProp.GetString() : null;
                var iocType = match.TryGetProperty("ioc_type", out var t) ? t.GetString() : null;

                sb.AppendLine();
                sb.AppendLine($"{idx + 1}.");
                sb.AppendLine($"IOC: {iocValue}");
                sb.AppendLine($"Type: {iocType}");
                sb.AppendLine($"Malware: {malware}");
                if (confidence.HasValue)
                {
                    sb.AppendLine($"Confidence: {confidence.Value}");
                }
                if (!string.IsNullOrEmpty(firstSeen))
                {
                    sb.AppendLine($"First Seen: {firstSeen}");
                }
                if (!string.IsNullOrEmpty(lastSeen))
                {
                    sb.AppendLine($"Last Seen: {lastSeen}");
                }
            }

            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                Duration = duration,
                NormalizedData = sb.ToString().TrimEnd()
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
                ErrorMessage = "Failed to parse ThreatFox response."
            };
        }
    }
}
