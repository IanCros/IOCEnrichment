namespace IOCX.Application.Providers;

using IOCX.Application;
using IOCX.Domain;

/// <summary>RDAP (Registration Data Access Protocol) enrichment provider.</summary>
public sealed class RdapProvider : IEnrichmentProvider
{
    private readonly IHttpClient _httpClient;
    private readonly IRateLimiter _rateLimiter;

    public RdapProvider(IHttpClient httpClient, IRateLimiter rateLimiter)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _rateLimiter = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    }

    /// <inheritdoc />
    public string Name => "RDAP";

    /// <inheritdoc />
    public bool Supports(Ioc ioc)
    {
        if (ioc is null)
        {
            throw new ArgumentNullException(nameof(ioc));
        }

        return ioc.Type is IocType.Domain;
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
                ErrorMessage = $"IOC type {ioc.Type} is not supported by RDAP."
            };
        }

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);

            var url = $"https://rdap.org/domain/{Uri.EscapeDataString(ioc.NormalizedValue)}";
            var startTime = DateTimeOffset.UtcNow;
            var response = await _httpClient.GetAsync(url, cancellationToken);
            var duration = (long)(DateTimeOffset.UtcNow - startTime).TotalMilliseconds;

            return response.StatusCode switch
            {
                System.Net.HttpStatusCode.OK => ProcessSuccessResponse(response.Content!, duration),
                System.Net.HttpStatusCode.NotFound => new ProviderResult
                {
                    ProviderName = Name,
                    Status = ProviderStatus.Unavailable,
                    Timestamp = DateTimeOffset.UtcNow,
                    Duration = duration,
                    ErrorMessage = "Domain not found in RDAP registry."
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
                ErrorMessage = "RDAP request timed out or was canceled."
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

            var handle = root.TryGetProperty("handle", out var h) ? h.GetString() : null;
            var registrar = root.TryGetProperty("entities", out var entities) && entities.GetArrayLength() > 0
                ? ExtractRegistrar(entities) : null;
            var creationDate = root.TryGetProperty("events", out var events)
                ? ExtractEventDate(events, "registration") : null;
            var lastChanged = root.TryGetProperty("events", out var events2)
                ? ExtractEventDate(events2, "last changed") : null;

            var nameservers = root.TryGetProperty("nameservers", out var ns) && ns.GetArrayLength() > 0
                ? ns.EnumerateArray().Select(x => x.TryGetProperty("ldhName", out var ldh) ? ldh.GetString() : x.TryGetProperty("unicodeName", out var un) ? un.GetString() : null)
                    .Where(x => x is not null).ToArray() : Array.Empty<string>();

            var statuses = root.TryGetProperty("status", out var st) && st.GetArrayLength() > 0
                ? st.EnumerateArray().Select(x => x.GetString()).Where(x => x is not null).ToArray() : Array.Empty<string>();

            var sb = new System.Text.StringBuilder();

            sb.AppendLine($"Domain handle: {handle ?? "Unknown"}");
            if (!string.IsNullOrEmpty(registrar)) sb.AppendLine($"Registrar: {registrar}");
            if (!string.IsNullOrEmpty(creationDate)) sb.AppendLine($"Created: {creationDate}");
            if (!string.IsNullOrEmpty(lastChanged)) sb.AppendLine($"Last Changed: {lastChanged}");

            if (nameservers.Length > 0)
            {
                sb.AppendLine("Nameservers:");
                foreach (var nsName in nameservers) sb.AppendLine($"  {nsName}");
            }

            if (statuses.Length > 0)
            {
                sb.AppendLine("Status:");
                foreach (var s in statuses) sb.AppendLine($"  {s}");
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
                ErrorMessage = "Failed to parse RDAP response."
            };
        }
    }

    private static string? ExtractRegistrar(System.Text.Json.JsonElement entities)
    {
        foreach (var entity in entities.EnumerateArray())
        {
            if (entity.TryGetProperty("roles", out var roles) && roles.EnumerateArray().Any(r => r.GetString() == "registrar"))
            {
                if (entity.TryGetProperty("vcardArray", out var vcardArray) && vcardArray.GetArrayLength() > 1)
                {
                    foreach (var vcard in vcardArray[1].EnumerateArray())
                    {
                        if (vcard.GetArrayLength() > 3)
                        {
                            var label = vcard[0].GetString();
                            if (label == "fn")
                            {
                                return vcard[3].GetString();
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    private static string? ExtractEventDate(System.Text.Json.JsonElement events, string action)
    {
        foreach (var evt in events.EnumerateArray())
        {
            if (evt.TryGetProperty("eventAction", out var actionProp) && actionProp.GetString() == action)
            {
                if (evt.TryGetProperty("eventDate", out var dateProp))
                {
                    return dateProp.GetString();
                }
            }
        }
        return null;
    }
}
