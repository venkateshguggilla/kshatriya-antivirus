using System.Text.Json;

namespace Kshatriya.BrowserHost;

/// <summary>A validated request from the browser extension (schema: docs/schemas/browser-host.v1.schema.json).</summary>
internal sealed record HostRequest(string Type, string? Path)
{
    public const int Version = 1;
    public const string Status = "status";
    public const string Scan = "scan";
    public const string Blocklist = "blocklist";
    private const int MaxPathChars = 32_767;

    /// <summary>
    /// Parses a request strictly: a JSON object with exactly the known properties, version 1, a known type,
    /// and a path only (and always) for scans. Returns null and an error code for anything else.
    /// </summary>
    public static HostRequest? Parse(byte[] utf8, out string? error)
    {
        error = HostErrors.InvalidRequest;
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(utf8, new JsonDocumentOptions { MaxDepth = 4 });
        }
        catch (JsonException)
        {
            return null;
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            int? version = null;
            string? type = null;
            string? path = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (!seen.Add(property.Name))
                {
                    return null;
                }

                switch (property.Name)
                {
                    case "v" when property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt32(out int v):
                        version = v;
                        break;
                    case "type" when property.Value.ValueKind == JsonValueKind.String:
                        type = property.Value.GetString();
                        break;
                    case "path" when property.Value.ValueKind == JsonValueKind.String:
                        path = property.Value.GetString();
                        break;
                    default:
                        return null;
                }
            }

            if (version != Version)
            {
                error = HostErrors.UnsupportedVersion;
                return null;
            }

            switch (type)
            {
                case Status or Blocklist when path is null:
                    error = null;
                    return new HostRequest(type, null);
                case Scan when path is not null:
                    if (!IsAcceptablePath(path))
                    {
                        error = HostErrors.InvalidPath;
                        return null;
                    }

                    error = null;
                    return new HostRequest(Scan, path);
                default:
                    return null;
            }
        }
    }

    /// <summary>A fully qualified local drive path (C:\...), not UNC, device (\\?\, \\.\) or relative.</summary>
    internal static bool IsAcceptablePath(string path) =>
        path.Length is >= 4 and <= MaxPathChars
        && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'
        && System.IO.Path.IsPathFullyQualified(path)
        && path.IndexOfAny(['*', '?', '"', '<', '>', '|', '\0']) < 0
        && path.IndexOf(':', 2) < 0;
}

/// <summary>Stable error codes sent to the extension.</summary>
internal static class HostErrors
{
    public const string InvalidRequest = "invalid-request";
    public const string UnsupportedVersion = "unsupported-version";
    public const string InvalidPath = "invalid-path";
    public const string NotAFile = "not-a-file";
    public const string ServiceUnavailable = "service-unavailable";
    public const string ScanFailed = "scan-failed";
    public const string BlocklistFailed = "blocklist-failed";
}
