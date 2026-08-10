namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>URLhaus threat intelligence provider.</summary>
public sealed class UrlhausProvider : IEnrichmentProvider
{
    private readonly IHttpClient _httpClient;
    private readonly IRateLimiter _rateLimiter;

    /// <summary>
    /// abuse.ch requires an Auth-Key header on every URLhaus request. Free keys are issued
    /// at https://auth.abuse.ch/. Requests without one are rejected with 401.
    /// </summary>
    private readonly string? _authKey;

    public UrlhausProvider(IHttpClient httpClient, IRateLimiter rateLimiter, string? authKey = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        _authKey = authKey;
    }

    /// <inheritdoc />
    public string Name => "URLhaus";

    /// <inheritdoc />
    public bool Supports(Ioc ioc)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        return ioc.Type is IocType.Url or IocType.Domain or IocType.IPv4 or IocType.IPv6;
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
                ErrorMessage = $"IOC type {ioc.Type} is not supported by URLhaus."
            };
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);

            var url = "https://urlhaus-api.abuse.ch/v1/url/";
            var startTime = DateTimeOffset.UtcNow;

            var requestBody = System.Text.Json.JsonSerializer.Serialize(new
            {
                url = ioc.Type == IocType.Url ? ioc.NormalizedValue : null,
                host = ioc.Type == IocType.Domain ? ioc.NormalizedValue : null
            });
            // For IPv4/IPv6, URLhaus supports host lookups
            if (ioc.Type is IocType.IPv4 or IocType.IPv6)
            {
                requestBody = System.Text.Json.JsonSerializer.Serialize(new
                {
                    host = ioc.NormalizedValue
                });
            }

            var headers = new Dictionary<string, string> { ["Accept"] = "application/json" };
            if (!string.IsNullOrWhiteSpace(_authKey))
            {
                headers["Auth-Key"] = _authKey;
            }

            var response = await _httpClient.PostAsync(url, requestBody, headers, cancellationToken);
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
            var root = data.RootElement;

            var queryStatus = root.TryGetProperty("query_status", out var statusProp) ? statusProp.GetString() : null;

            if (queryStatus is null or "no_results")
            {
                return new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Success,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    NormalizedData = "No URLhaus matches found.",
                    Findings = new ProviderFindings { ThreatMatches = new ThreatMatchFacts(0) }
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
                    ErrorMessage = $"URLhaus query status: {queryStatus}"
                };
            }

            // Handle single result vs multiple results
            List<System.Text.Json.JsonElement> results = new();
            if (root.TryGetProperty("url_id", out _))
            {
                results.Add(root);
            }
            else if (root.TryGetProperty("data", out var dataArray) && dataArray.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                results.AddRange(dataArray.EnumerateArray());
            }

            if (results.Count == 0)
            {
                results.Add(root);
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Matches: {results.Count}");

            var families = new List<string>();
            var allTags = new List<string>();
            var related = new List<RelatedIndicator>();
            var anyOnline = false;
            DateTimeOffset? latestSeen = null;

            foreach (var result in results)
            {
                var url = result.TryGetProperty("url", out var urlProp) ? urlProp.GetString() : null;
                var urlStatus = result.TryGetProperty("url_status", out var us) ? us.GetString() : null;
                var threat = result.TryGetProperty("threat", out var t) ? t.GetString() : null;
                var malware = result.TryGetProperty("malware", out var m) ? m.GetString() : null;
                var dateAdded = result.TryGetProperty("date_added", out var da) ? da.GetString() : null;
                var lastOnline = result.TryGetProperty("last_online", out var lo) ? lo.GetString() : null;
                var reporter = result.TryGetProperty("reporter", out var r) ? r.GetString() : null;
                var tags = result.TryGetProperty("tags", out var tg) ? tg.EnumerateArray().Select(x => x.GetString()).ToArray() : Array.Empty<string>();
                var host = result.TryGetProperty("host", out var h) ? h.GetString() : null;
                var ip = result.TryGetProperty("ip_address", out var ipProp) ? ipProp.GetString() : null;

                sb.AppendLine();
                if (!string.IsNullOrEmpty(url)) sb.AppendLine($"URL: {url}");
                if (!string.IsNullOrEmpty(urlStatus)) sb.AppendLine($"Status: {urlStatus}");
                if (!string.IsNullOrEmpty(threat)) sb.AppendLine($"Threat: {threat}");
                if (!string.IsNullOrEmpty(malware)) sb.AppendLine($"Malware: {malware}");
                if (!string.IsNullOrEmpty(host)) sb.AppendLine($"Host: {host}");
                if (!string.IsNullOrEmpty(ip)) sb.AppendLine($"IP: {ip}");
                if (!string.IsNullOrEmpty(dateAdded)) sb.AppendLine($"Date Added: {dateAdded}");
                if (!string.IsNullOrEmpty(lastOnline)) sb.AppendLine($"Last Online: {lastOnline}");
                if (!string.IsNullOrEmpty(reporter)) sb.AppendLine($"Reporter: {reporter}");
                if (tags.Length > 0)
                {
                    sb.AppendLine("Tags: " + string.Join(", ", tags));
                }

                if (!string.IsNullOrWhiteSpace(malware) && !families.Contains(malware, StringComparer.OrdinalIgnoreCase))
                {
                    families.Add(malware);
                }

                foreach (var tag in tags)
                {
                    if (!string.IsNullOrWhiteSpace(tag) && !allTags.Contains(tag, StringComparer.OrdinalIgnoreCase))
                    {
                        allTags.Add(tag);
                    }
                }

                if (string.Equals(urlStatus, "online", StringComparison.OrdinalIgnoreCase))
                {
                    anyOnline = true;
                }

                if (DateTimeOffset.TryParse(dateAdded, out var parsedAdded)
                    && (latestSeen is null || parsedAdded > latestSeen))
                {
                    latestSeen = parsedAdded;
                }

                if (!string.IsNullOrWhiteSpace(ip))
                {
                    related.Add(new RelatedIndicator(ip, null, RelationshipType.HostedOn, 80));
                }

                if (!string.IsNullOrWhiteSpace(host))
                {
                    related.Add(new RelatedIndicator(host, null, RelationshipType.RelatedTo, 70));
                }
            }

            return new ProviderResult
            {
                ProviderName = Name,
                Status = ProviderStatus.Success,
                Timestamp = DateTimeOffset.UtcNow,
                Duration = duration,
                NormalizedData = sb.ToString().TrimEnd(),
                Findings = new ProviderFindings
                {
                    ThreatMatches = new ThreatMatchFacts(
                        results.Count,
                        families,
                        allTags,
                        FirstSeen: null,
                        LastSeen: latestSeen,
                        IsActive: anyOnline),
                    Related = related,
                    LastActivityAt = latestSeen
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
                ErrorMessage = "Failed to parse URLhaus response."
            };
        }
    }
}
