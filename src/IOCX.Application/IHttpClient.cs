namespace IOCX.Application;

using System.Net;

/// <summary>Represents the result of an HTTP request.</summary>
public sealed class HttpResponseResult
{
    public HttpStatusCode StatusCode { get; init; }

    public string? Content { get; init; }

    public bool IsSuccess => StatusCode is >= HttpStatusCode.OK and < HttpStatusCode.BadRequest;

    public string? ErrorMessage { get; init; }
}

/// <summary>
/// HTTP abstraction shared by every provider. Headers usually carry provider credentials,
/// so their values must never be logged.
/// </summary>
public interface IHttpClient : IDisposable
{

    Task<HttpResponseResult> GetAsync(
        string url,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken cancellationToken = default);


    Task<HttpResponseResult> PostAsync(
        string url,
        string? content = null,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken cancellationToken = default);
}
