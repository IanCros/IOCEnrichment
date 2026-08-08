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
    }

    /// <inheritdoc />
    public async Task<HttpResponseResult> GetAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            using var response = await _client.GetAsync(url, cancellationToken);
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
    public async Task<HttpResponseResult> PostAsync(string url, string? content = null, CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url);

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

    /// <inheritdoc />
    public void Dispose()
    {
        _client.Dispose();
    }
}
