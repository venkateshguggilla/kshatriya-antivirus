using System.Text.Json;
using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Updates;

namespace Kshatriya.BrowserHost;

/// <summary>What the host asks of the Kshatriya service.</summary>
internal interface IHostService
{
    Task<string> GetVersionAsync(CancellationToken cancellationToken);

    /// <summary>Report-only scan of one file, performed by the service as the signed-in user.</summary>
    Task<ScanReport> ScanFileAsync(string path, CancellationToken cancellationToken);

    /// <summary>One page of the dangerous web sites from the service's installed content (ADR 0019).</summary>
    Task<WebBlocklistReplyDto> GetWebBlocklistAsync(int offset, int maxBytes, CancellationToken cancellationToken);
}

/// <summary>Answers one request. The host never opens the file; it only checks the path and asks the service.</summary>
internal sealed class HostHandler(IHostService service, Func<string, bool> isExistingFile)
{
    private const int MaxDetections = 10;
    private const int MaxText = 200;

    public async Task<byte[]> HandleAsync(byte[] request, CancellationToken cancellationToken)
    {
        HostRequest? parsed = HostRequest.Parse(request, out string? error);
        if (parsed is null)
        {
            return error == HostErrors.InvalidPath
                ? Error("error", error, "Only files on this PC's own drives can be scanned.")
                : Error("error", error ?? HostErrors.InvalidRequest, "The request was not understood.");
        }

        if (parsed.Type == HostRequest.Scan && !isExistingFile(parsed.Path!))
        {
            return Error(parsed.Type, HostErrors.NotAFile, "Only existing files can be scanned from the browser.");
        }

        try
        {
            if (parsed.Type == HostRequest.Status)
            {
                string version = await service.GetVersionAsync(cancellationToken);
                return Write(json =>
                {
                    Begin(json, HostRequest.Status, ok: true);
                    json.WriteString("serviceVersion", Clip(version));
                });
            }

            if (parsed.Type == HostRequest.Blocklist)
            {
                return BlocklistReply(await service.GetWebBlocklistAsync(parsed.Offset, WebBlockList.MaxPageBytes, cancellationToken));
            }

            ScanReport report = await service.ScanFileAsync(parsed.Path!, cancellationToken);
            return ScanReply(report);
        }
        catch (Exception ex) when (ex is ServiceException { InnerException: TimeoutException }
                                   or TimeoutException or IOException or UnauthorizedAccessException)
        {
            return Error(parsed.Type, HostErrors.ServiceUnavailable, "The Kshatriya service is not running.");
        }
        catch (ServiceException ex)
        {
            return Error(parsed.Type, parsed.Type == HostRequest.Blocklist ? HostErrors.BlocklistFailed : HostErrors.ScanFailed, Clip(ex.Message));
        }
    }

    /// <summary>
    /// A page of the service's list, re-checked here: the extension turns it into browser rules, so only
    /// well-formed domains within the limits are passed on, and the reply must fit in one native message.
    /// </summary>
    internal static byte[] BlocklistReply(WebBlocklistReplyDto list)
    {
        bool consistent = list.Sequence >= 0 && list.Total is >= 0 and <= WebBlockList.MaxDomains
            && list.Offset >= 0 && list.Next == list.Offset + list.Domains.Count && list.Next <= list.Total
            && (list.Domains.Count > 0 || list.Next == list.Total);
        if (!consistent || !list.Domains.All(WebBlockList.IsBlockable))
        {
            return Error(HostRequest.Blocklist, HostErrors.BlocklistFailed, "The Kshatriya service sent an invalid web blocklist.");
        }

        byte[] reply = Write(json =>
        {
            Begin(json, HostRequest.Blocklist, ok: true);
            json.WriteNumber("sequence", list.Sequence);
            json.WriteNumber("total", list.Total);
            json.WriteNumber("offset", list.Offset);
            json.WriteNumber("next", list.Next);
            json.WriteStartArray("domains");
            foreach (string domain in list.Domains)
            {
                json.WriteStringValue(domain);
            }

            json.WriteEndArray();
        });
        return reply.Length <= NativeFraming.MaxReplyBytes
            ? reply
            : Error(HostRequest.Blocklist, HostErrors.BlocklistFailed, "The web blocklist is too large to send to the browser.");
    }

    internal static byte[] ScanReply(ScanReport report)
    {
        IReadOnlyList<ScanItemResult> items = report.Items;
        ScanItemResult? worst =
            items.FirstOrDefault(i => i.Status == ScanStatus.Detected)
            ?? items.FirstOrDefault(i => i.Status == ScanStatus.Suspicious)
            ?? items.FirstOrDefault(i => i.Status == ScanStatus.NotScanned)
            ?? items.FirstOrDefault(i => i.Status == ScanStatus.Skipped);
        ScanStatus status = worst?.Status ?? ScanStatus.Clean;

        return Write(json =>
        {
            Begin(json, HostRequest.Scan, ok: true);
            json.WriteString("status", WireNames.Of(status));
            if (worst is not null && worst.Reason != ScanReason.None)
            {
                json.WriteString("reason", WireNames.Of(worst.Reason));
            }

            json.WriteStartArray("detections");
            foreach (Detection d in items.SelectMany(i => i.Detections).Take(MaxDetections))
            {
                json.WriteStartObject();
                json.WriteString("name", Clip(d.Name));
                json.WriteString("category", WireNames.Of(d.Category));
                json.WriteString("confidence", WireNames.Of(d.Confidence));
                json.WriteEndObject();
            }

            json.WriteEndArray();
        });
    }

    internal static byte[] Error(string type, string code, string message) => Write(json =>
    {
        Begin(json, type, ok: false);
        json.WriteString("error", code);
        json.WriteString("message", message);
    });

    private static void Begin(Utf8JsonWriter json, string type, bool ok)
    {
        json.WriteNumber("v", HostRequest.Version);
        json.WriteString("type", type);
        json.WriteBoolean("ok", ok);
    }

    private static byte[] Write(Action<Utf8JsonWriter> body)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            body(json);
            json.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static string Clip(string text) => text.Length <= MaxText ? text : text[..MaxText];
}

/// <summary>Talks to the installed service over its authenticated pipe, one connection per request.</summary>
internal sealed class ServiceHostAdapter(ServiceEndpoint endpoint) : IHostService
{
    private static readonly TimeSpan s_connectTimeout = TimeSpan.FromSeconds(3);

    public async Task<string> GetVersionAsync(CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ServiceClient.ConnectAsync(endpoint, "kshatriya-browser-host", s_connectTimeout, cancellationToken);
        return (await client.GetStatusAsync(cancellationToken)).Version;
    }

    public async Task<ScanReport> ScanFileAsync(string path, CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ServiceClient.ConnectAsync(endpoint, "kshatriya-browser-host", s_connectTimeout, cancellationToken);
        return await client.ScanAsync([path], includeClean: false, quarantine: false, cancellationToken: cancellationToken);
    }

    public async Task<WebBlocklistReplyDto> GetWebBlocklistAsync(int offset, int maxBytes, CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ServiceClient.ConnectAsync(endpoint, "kshatriya-browser-host", s_connectTimeout, cancellationToken);
        return await client.GetWebBlocklistAsync(offset, maxBytes, cancellationToken);
    }
}
