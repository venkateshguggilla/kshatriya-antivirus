using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Kshatriya.Updates;

namespace Kshatriya.Mobile;

/// <summary>What one update check did.</summary>
public enum UpdateCheckOutcome
{
    /// <summary>A newer package was downloaded, verified and installed.</summary>
    Installed,

    /// <summary>The source offers the update that is already installed (or the server says nothing changed).</summary>
    UpToDate,

    /// <summary>The download or the package failed; the installed content is unchanged.</summary>
    Failed,
}

/// <summary>Result of an update check, with a sentence for the screen.</summary>
public sealed record UpdateCheckResult(UpdateCheckOutcome Outcome, string Message, long Sequence = 0, string? Code = null);

/// <summary>When the last check ran and how it went, for the screen.</summary>
public sealed record UpdateCheckStatus(DateTimeOffset? LastCheckUtc, DateTimeOffset? LastSuccessUtc, string? LastMessage);

/// <summary>
/// Downloads the signed content package from one HTTPS address and installs it through
/// <see cref="MobileContentStore.Import"/> (ADR 0020, point 12). The download is not trusted: the package's
/// signature, hashes, expiry and sequence decide, exactly as for a package the user imports by hand.
/// The request carries no identifiers (no cookies, no device or user id, a generic User-Agent).
/// </summary>
public sealed class ContentUpdateChecker
{
    /// <summary>Largest package accepted from the network.</summary>
    public const int MaxDownloadBytes = 64 * 1024 * 1024;

    /// <summary>The user agent sent with every request: product and version only.</summary>
    public const string UserAgent = "Kshatriya-Android/0.1";

    private const string StateFile = "update-check.json";
    private static readonly TimeSpan s_timeout = TimeSpan.FromMinutes(2);
    private readonly MobileContentStore _store;
    private readonly HttpMessageHandler _handler;
    private readonly string _statePath;
    // One check at a time in the process: the scheduled job and "Check now" can start together.
    private static readonly SemaphoreSlim s_gate = new(1, 1);

    /// <param name="store">The content store the package is imported into.</param>
    /// <param name="handler">The HTTP handler (the platform's on Android; a fake in tests). Not disposed.</param>
    /// <param name="folder">App-private folder for the check state (validators and last result).</param>
    public ContentUpdateChecker(MobileContentStore store, HttpMessageHandler handler, string folder)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentException.ThrowIfNullOrEmpty(folder);
        _store = store;
        _handler = handler;
        Directory.CreateDirectory(folder);
        _statePath = Path.Combine(folder, StateFile);
    }

    /// <summary>
    /// Checks a source address: absolute <c>https</c>, a host, no user name or password in it. Returns null if
    /// it is acceptable, otherwise the reason.
    /// </summary>
    public static string? ValidateSource(string? text)
    {
        if (!Uri.TryCreate(text?.Trim(), UriKind.Absolute, out Uri? uri))
        {
            return "Enter a full address starting with https://.";
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return "Only https:// addresses are allowed.";
        }

        if (string.IsNullOrEmpty(uri.Host) || uri.HostNameType == UriHostNameType.Unknown)
        {
            return "The address has no host name.";
        }

        return uri.UserInfo.Length > 0 ? "The address must not contain a user name or password." : null;
    }

    /// <summary>The last check's time and result.</summary>
    public UpdateCheckStatus Status
    {
        get
        {
            CheckState state = ReadState();
            return new UpdateCheckStatus(state.LastCheckUtc, state.LastSuccessUtc, state.LastMessage);
        }
    }

    /// <summary>Downloads the package from <paramref name="source"/> if it changed, and installs it if newer.</summary>
    public async Task<UpdateCheckResult> CheckAsync(string source, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (ValidateSource(source) is { } invalid)
        {
            return new UpdateCheckResult(UpdateCheckOutcome.Failed, invalid, Code: "source_invalid");
        }

        await s_gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CheckState state = ReadState();
            var uri = new Uri(source.Trim());
            // Validators belong to one address; a new address downloads afresh.
            bool sameSource = state.Source == uri.AbsoluteUri;
            UpdateCheckResult result;
            string? etag = null;
            string? lastModified = null;
            try
            {
                (result, etag, lastModified) = await DownloadAndImportAsync(uri, sameSource ? state : null, now, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
            {
                result = new UpdateCheckResult(UpdateCheckOutcome.Failed, $"Could not download the update: {ex.Message}", Code: "download_failed");
            }

            state.Source = uri.AbsoluteUri;
            state.LastCheckUtc = now;
            state.LastMessage = result.Message;
            if (result.Outcome != UpdateCheckOutcome.Failed)
            {
                state.LastSuccessUtc = now;
                // Keep validators only for a package that was accepted or already installed, so a bad download
                // is fetched again instead of being answered "not modified".
                if (etag is not null || lastModified is not null)
                {
                    state.ETag = etag;
                    state.LastModified = lastModified;
                }
            }
            else if (!sameSource)
            {
                state.ETag = null;
                state.LastModified = null;
            }

            WriteState(state);
            return result;
        }
        finally
        {
            s_gate.Release();
        }
    }

    private async Task<(UpdateCheckResult Result, string? ETag, string? LastModified)> DownloadAndImportAsync(Uri uri, CheckState? validators, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var client = new HttpClient(_handler, disposeHandler: false) { Timeout = s_timeout };
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd(UserAgent);
        if (validators?.ETag is { } etag && EntityTagHeaderValue.TryParse(etag, out EntityTagHeaderValue? tag))
        {
            request.Headers.IfNoneMatch.Add(tag);
        }

        if (validators?.LastModified is { } modified && DateTimeOffset.TryParse(modified, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out DateTimeOffset since))
        {
            request.Headers.IfModifiedSince = since;
        }

        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        // The final address after redirects must still be https (HttpClient does not follow https to http,
        // but check rather than rely on the platform handler).
        if (response.RequestMessage?.RequestUri is { } final && final.Scheme != Uri.UriSchemeHttps)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.Failed, "The update address redirected to a non-https address.", Code: "insecure_redirect"), null, null);
        }

        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.UpToDate, "No new update (the server reports no change)."), validators?.ETag, validators?.LastModified);
        }

        if (!response.IsSuccessStatusCode)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.Failed, $"The update server answered {(int)response.StatusCode} {response.ReasonPhrase}.", Code: "http_status"), null, null);
        }

        if (response.Content.Headers.ContentLength > MaxDownloadBytes)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.Failed, "The update is larger than the download limit.", Code: "too_large"), null, null);
        }

        byte[]? package = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        if (package is null)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.Failed, "The update is larger than the download limit.", Code: "too_large"), null, null);
        }

        string? newTag = response.Headers.ETag?.ToString();
        string? newModified = response.Content.Headers.LastModified?.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
        long installed = _store.InstalledSequence;
        ContentImportResult import = _store.Import(package, now);
        if (import.Succeeded)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.Installed, import.Message, import.Sequence), newTag, newModified);
        }

        // The same package as the one installed is not an error: the source simply has nothing newer.
        if (import.Code == ContentErrors.Rollback && import.Sequence == installed && installed > 0)
        {
            return (new UpdateCheckResult(UpdateCheckOutcome.UpToDate, $"No new update; update {installed} is the latest.", installed), newTag, newModified);
        }

        return (new UpdateCheckResult(UpdateCheckOutcome.Failed, $"The downloaded update was refused: {import.Message}", Code: import.Code), null, null);
    }

    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxDownloadBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private CheckState ReadState()
    {
        try
        {
            return File.Exists(_statePath)
                ? JsonSerializer.Deserialize(File.ReadAllText(_statePath), CheckJsonContext.Default.CheckState) ?? new CheckState()
                : new CheckState();
        }
        catch (JsonException)
        {
            return new CheckState(); // a damaged state file only costs one full download
        }
    }

    private void WriteState(CheckState state)
    {
        string temporary = _statePath + ".new";
        File.WriteAllText(temporary, JsonSerializer.Serialize(state, CheckJsonContext.Default.CheckState));
        File.Move(temporary, _statePath, overwrite: true);
    }
}

internal sealed class CheckState
{
    public string? Source { get; set; }

    public string? ETag { get; set; }

    public string? LastModified { get; set; }

    public DateTimeOffset? LastCheckUtc { get; set; }

    public DateTimeOffset? LastSuccessUtc { get; set; }

    public string? LastMessage { get; set; }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(CheckState))]
internal sealed partial class CheckJsonContext : System.Text.Json.Serialization.JsonSerializerContext
{
}
