namespace IOCX.Application;

using System.Net;
using System.Net.Http.Json;

/// <summary>Implementation of <see cref="IHttpClient"/> using System.Net.Http.HttpClient.</summary>
public sealed class HttpClientWrapper : IHttpClient
{
    private readonly HttpClient _client;
    private readonly TimeSpan _timeout;

    public HttpClientWrapper(HttpMessageHandler? handler = null, TimeSpan? timeout = null)
    {
        _client = handler is null ? new HttpClient() : new HttpClient(handler);
        _timeout = timeout ?? TimeSpan.FromSeconds(15);
        _client.Timeout = _timeout;

        // .NET sends no User-Agent by default. Several providers — RDAP registries in
        // particular — reject such requests with 403, so identify the client explicitly.
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("IOC-X/1.0 (threat-intelligence-analysis)");
    }

    /// <inheritdoc />
    public async Task<HttpResponseResult> GetAsync(
        string url,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            ApplyHeaders(request, headers);

            using var response = await _client.SendAsync(request, cancellationToken);
            var content = await response.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseResult
            {
                StatusCode = response.StatusCode,
                Content = content,
                ErrorMessage = response.IsSuccessStatusCode ? null : $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}"
            };
        }
        catch (OperationCanceledException)
        {
            return new HttpResponseResult
            {
                StatusCode = HttpStatusCode.RequestTimeout,
                ErrorMessage = "Request timed out."
            };
        }
        catch (HttpRequestException ex)
        {
            return new HttpResponseResult
            {
                StatusCode = HttpStatusCode.ServiceUnavailable,
                ErrorMessage = $"HTTP error: {ex.Message}"
            };
        }
    }

    /// <inheritdoc />
    public async Task<HttpResponseResult> PostAsync(
        string url,
        string? content = null,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            ApplyHeaders(request, headers);

            if (content is not null)
            {
                request.Content = new StringContent(content);
            }

            using var response = await _client.SendAsync(request, cancellationToken);
            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseResult
            {
                StatusCode = response.StatusCode,
                Content = responseContent,
                ErrorMessage = response.IsSuccessStatusCode ? null : $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}"
            };
        }
        catch (OperationCanceledException)
        {
            return new HttpResponseResult
            {
                StatusCode = HttpStatusCode.RequestTimeout,
                ErrorMessage = "Request timed out."
            };
        }
        catch (HttpRequestException ex)
        {
            return new HttpResponseResult
            {
                StatusCode = HttpStatusCode.ServiceUnavailable,
                ErrorMessage = $"HTTP error: {ex.Message}"
            };
        }
    }

    /// <summary>Applies caller-supplied headers to a request.</summary>
    /// <remarks>
    /// Headers are set per request rather than on the shared <see cref="HttpClient"/>, so one
    /// provider's credentials can never be sent to a different provider's endpoint.
    /// </remarks>
    private static void ApplyHeaders(HttpRequestMessage request, IReadOnlyDictionary<string, string>? headers)
    {
        if (headers is null)
        {
            return;
        }

        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _client.Dispose();
    }
}
