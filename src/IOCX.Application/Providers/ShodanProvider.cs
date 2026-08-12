namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>Shodan threat intelligence provider.</summary>
public sealed class ShodanProvider : IEnrichmentProvider
{
    private readonly IHttpClient _httpClient;
    private readonly IRateLimiter _rateLimiter;
    private readonly string _apiKey;

    public ShodanProvider(IHttpClient httpClient, IRateLimiter rateLimiter, string apiKey)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
    }

    /// <inheritdoc />
    public string Name => "Shodan";

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
                ErrorMessage = $"IOC type {ioc.Type} is not supported by Shodan."
            };
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);

            var url = $"https://api.shodan.io/shodan/host/{ioc.NormalizedValue}?key={Uri.EscapeDataString(_apiKey)}";
            var startTime = DateTimeOffset.UtcNow;
            // Shodan authenticates with a query-string parameter rather than a header.
            var response = await _httpClient.GetAsync(url, headers: null, cancellationToken);
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
                    ErrorMessage = "IP not found in Shodan database."
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
                    ErrorMessage = Redact($"HTTP {(int)response.StatusCode}: {response.ErrorMessage}")
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
                ErrorMessage = Redact($"Error: {ex.Message}")
            };
        }
    }

    /// <summary>Removes the API key from a message before it can be displayed or persisted.</summary>
    /// <remarks>
    /// Shodan authenticates by query-string parameter, so this provider is the only one whose
    /// credential travels inside a URL. Exception and transport messages do not normally echo
    /// the query string, but an error message is written to the investigation record and shown
    /// in the UI, so the key is stripped rather than trusted not to appear.
    /// </remarks>
    private string Redact(string message) =>
        string.IsNullOrEmpty(_apiKey)
            ? message
            : message
                .Replace(_apiKey, "[redacted]", StringComparison.Ordinal)
                .Replace(Uri.EscapeDataString(_apiKey), "[redacted]", StringComparison.Ordinal);

    private ProviderResult ProcessSuccessResponse(string content, long duration)
    {
        try
        {
            var data = System.Text.Json.JsonDocument.Parse(content);
            var root = data.RootElement;

            var ip = root.TryGetProperty("ip_str", out var ipProp) ? ipProp.GetString() : null;
            var org = root.TryGetProperty("org", out var o) ? o.GetString() : null;
            var isp = root.TryGetProperty("isp", out var i) ? i.GetString() : null;
            var asn = root.TryGetProperty("asn", out var a) ? a.GetString() : null;
            var country = root.TryGetProperty("country_name", out var c) ? c.GetString() : null;
            var city = root.TryGetProperty("city", out var cityProp) ? cityProp.GetString() : null;
            var region = root.TryGetProperty("region_name", out var r) ? r.GetString() : null;
            var lastUpdate = root.TryGetProperty("last_update", out var lu) ? lu.GetString() : null;

            var hostnames = root.TryGetProperty("hostnames", out var h) ? h.EnumerateArray().Select(x => x.GetString()).ToArray() : Array.Empty<string>();
            var domains = root.TryGetProperty("domains", out var d) ? d.EnumerateArray().Select(x => x.GetString()).ToArray() : Array.Empty<string>();
            var ports = root.TryGetProperty("ports", out var p) ? p.EnumerateArray().Select(x => x.GetInt32()).ToArray() : Array.Empty<int>();

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"IP: {ip}");
            if (!string.IsNullOrEmpty(org)) sb.AppendLine($"Organization: {org}");
            if (!string.IsNullOrEmpty(isp)) sb.AppendLine($"ISP: {isp}");
            if (!string.IsNullOrEmpty(asn)) sb.AppendLine($"ASN: {asn}");
            if (!string.IsNullOrEmpty(country)) sb.AppendLine($"Country: {country}");
            if (!string.IsNullOrEmpty(city)) sb.AppendLine($"City: {city}");
            if (!string.IsNullOrEmpty(region)) sb.AppendLine($"Region: {region}");
            if (!string.IsNullOrEmpty(lastUpdate)) sb.AppendLine($"Last Update: {lastUpdate}");

            if (hostnames.Length > 0)
            {
                sb.AppendLine("Hostnames:");
                foreach (var hn in hostnames) sb.AppendLine($"  {hn}");
            }

            if (domains.Length > 0)
            {
                sb.AppendLine("Domains:");
                foreach (var dm in domains) sb.AppendLine($"  {dm}");
            }

            // Extract services from data array
            if (root.TryGetProperty("data", out var services) && services.GetArrayLength() > 0)
            {
                sb.AppendLine("\nServices:");
                foreach (var service in services.EnumerateArray())
                {
                    var port = service.TryGetProperty("port", out var portProp) ? portProp.GetInt32() : 0;
                    var product = service.TryGetProperty("product", out var prod) ? prod.GetString() : null;
                    var version = service.TryGetProperty("version", out var v) ? v.GetString() : null;

                    sb.AppendLine($"  Port {port}:");
                    if (!string.IsNullOrEmpty(product)) sb.AppendLine($"    Product: {product}");
                    if (!string.IsNullOrEmpty(version)) sb.AppendLine($"    Version: {version}");
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
                ErrorMessage = "Failed to parse Shodan response."
            };
        }
    }
}
