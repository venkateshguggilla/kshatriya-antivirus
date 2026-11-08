using System.Globalization;
using System.Text;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Response;
using Sentinel.Runtime.Ipc;

namespace Sentinel.Cli;

/// <summary>quarantine, exclusions and audit commands, against the local vault or the service.</summary>
internal static class ManagementCommands
{
    /// <summary>Overrides the local data folder (tests). Null uses %LOCALAPPDATA%\Sentinel\local.</summary>
    public static string? LocalDataOverride { get; set; }

    public static string LocalDataDirectory =>
        LocalDataOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel", "local");

    /// <summary>The CLI's own per-user vault and audit log (no service involved).</summary>
    public static QuarantineManager OpenLocal() => new(
        QuarantineVault.Open(Path.Combine(LocalDataDirectory, "quarantine"), StorageAccess.CurrentUser),
        AuditLog.Open(Path.Combine(LocalDataDirectory, "audit"), StorageAccess.CurrentUser));

    public static async Task<int> QuarantineAsync(CliOptions options, Func<Task<ServiceClient>> connect, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        if (!options.UseService)
        {
            return await LocalQuarantineAsync(options, stdout, stderr);
        }

        await using ServiceClient client = await connect();
        switch (options.Action)
        {
            case "list":
                QuarantineListReplyDto list = await client.ListQuarantineAsync(ct);
                await stdout.WriteAsync(FormatList(list.Items.Select(i => (i.Id, i.QuarantinedUtc, i.SizeBytes, i.OriginalPath, i.User, (IReadOnlyList<string>)i.Detections))));
                return ExitCodes.Clean;
            case "add":
                return await ReportOperationAsync(await client.QuarantineFileAsync(options.Argument!, ct), "quarantine", stdout, stderr);
            case "restore":
                return await ReportOperationAsync(await client.RestoreAsync(options.Argument!, options.RestoreTo, ct), "restore", stdout, stderr);
            default:
                return await ReportOperationAsync(await client.DeleteQuarantinedAsync(options.Argument!, ct), "delete", stdout, stderr);
        }
    }

    public static async Task<int> ExclusionsAsync(CliOptions options, Func<Task<ServiceClient>> connect, TextWriter stdout, CancellationToken ct)
    {
        await using ServiceClient client = await connect();
        ExclusionsReplyDto reply = options.Action switch
        {
            "add" => await client.ChangeExclusionAsync(add: true, options.Argument!, ct),
            "remove" => await client.ChangeExclusionAsync(add: false, options.Argument!, ct),
            _ => await client.GetExclusionsAsync(ct),
        };

        var sb = new StringBuilder();
        if (reply.Paths.Count == 0 && reply.Sha256.Count == 0)
        {
            sb.AppendLine("No exclusions.");
        }

        foreach (string path in reply.Paths)
        {
            sb.Append("path    ").AppendLine(path);
        }

        foreach (string hash in reply.Sha256)
        {
            sb.Append("sha256  ").AppendLine(hash);
        }

        sb.AppendLine("Exclusions apply to Sentinel scans only. Excluded items are listed as skipped in every report.");
        await stdout.WriteAsync(sb.ToString());
        return ExitCodes.Clean;
    }

    public static async Task<int> UpdateAsync(CliOptions options, Func<Task<ServiceClient>> connect, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        await using ServiceClient client = await connect();
        ContentImportReplyDto reply = await client.ImportContentAsync(options.Argument!, ct);
        if (!reply.Succeeded)
        {
            await stderr.WriteLineAsync($"error: the content package was refused [{reply.Code}]: {reply.Message}");
            return ExitCodes.Fatal;
        }

        await stdout.WriteLineAsync($"{reply.Message} Valid until {reply.ExpiresUtc}.");
        return ExitCodes.Clean;
    }

    public static async Task<int> AuditAsync(CliOptions options, Func<Task<ServiceClient>> connect, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        IEnumerable<(long Seq, string Time, string User, string Action, string Outcome, string Target, string? Detail)> records;
        bool valid;
        string? problem;
        if (options.UseService)
        {
            await using ServiceClient client = await connect();
            AuditReplyDto reply = await client.GetAuditAsync(options.AuditLast, ct);
            records = reply.Records.Select(r => (r.Seq, r.TimeUtc, r.User, r.Action, r.Outcome, r.Target, r.Detail));
            (valid, problem) = (reply.ChainValid, reply.Problem);
        }
        else
        {
            AuditLog log = OpenLocal().Audit;
            records = log.ReadRecent(options.AuditLast).Select(r => (r.Sequence, Iso(r.TimeUtc), r.ActorName, r.Action, r.Outcome, r.Target, r.Detail));
            AuditVerification verification = log.Verify();
            (valid, problem) = (verification.Valid, verification.Problem);
        }

        var sb = new StringBuilder();
        foreach (var r in records)
        {
            sb.Append(CultureInfo.InvariantCulture, $"#{r.Seq}  {r.Time}  {r.User}  {r.Action} {r.Outcome}  {r.Target}");
            if (r.Detail is not null)
            {
                sb.Append("  (").Append(r.Detail).Append(')');
            }

            sb.AppendLine();
        }

        if (sb.Length == 0)
        {
            sb.AppendLine("No audit records.");
        }

        await stdout.WriteAsync(sb.ToString());
        if (!valid)
        {
            await stderr.WriteLineAsync($"warning: the audit log failed its integrity check: {problem}");
            return ExitCodes.Fatal;
        }

        await stdout.WriteLineAsync("Audit log integrity check passed (hash chain intact).");
        return ExitCodes.Clean;
    }

    private static async Task<int> LocalQuarantineAsync(CliOptions options, TextWriter stdout, TextWriter stderr)
    {
        QuarantineManager manager = OpenLocal();
        Actor me = Actor.Current();
        switch (options.Action)
        {
            case "list":
                await stdout.WriteAsync(FormatList(manager.List().Select(e => (e.Id, Iso(e.QuarantinedUtc), e.SizeBytes, e.OriginalPath, e.ActorName, e.Detections))));
                return ExitCodes.Clean;
            case "add":
                QuarantineResult added = manager.Quarantine(options.Argument!, me, [], expectedSha256: null, origin: "manual");
                return await ReportOperationAsync(
                    new OperationReplyDto { Succeeded = added.Succeeded, Code = WireNames.Of(added.Failure), Message = added.Message, QuarantineId = added.Entry?.Id, Path = options.Argument },
                    "quarantine",
                    stdout,
                    stderr);
            case "restore":
                RestoreResult restored = manager.Restore(options.Argument!, options.RestoreTo, me);
                return await ReportOperationAsync(
                    new OperationReplyDto
                    {
                        Succeeded = restored.Succeeded,
                        Code = RestoreResult.WireName(restored.Failure),
                        Message = restored.Succeeded && !restored.MarkOfTheWeb ? "Restored, but the internet zone mark could not be written on this volume." : restored.Message,
                        QuarantineId = options.Argument,
                        Path = restored.RestoredPath,
                    },
                    "restore",
                    stdout,
                    stderr);
            default:
                bool deleted = manager.Delete(options.Argument!, me);
                return await ReportOperationAsync(
                    new OperationReplyDto { Succeeded = deleted, Code = deleted ? "none" : "notFound", Message = deleted ? null : $"No quarantined item with id '{options.Argument}'.", QuarantineId = options.Argument },
                    "delete",
                    stdout,
                    stderr);
        }
    }

    private static async Task<int> ReportOperationAsync(OperationReplyDto reply, string operation, TextWriter stdout, TextWriter stderr)
    {
        if (!reply.Succeeded)
        {
            await stderr.WriteLineAsync($"error: {operation} failed [{reply.Code}]: {reply.Message}");
            return ExitCodes.Fatal;
        }

        string text = operation switch
        {
            "quarantine" => $"Quarantined {reply.Path} (id {reply.QuarantineId}).",
            "restore" => $"Restored {reply.QuarantineId} to {reply.Path}. It is marked as downloaded from the internet; it will be detected again by the next scan unless excluded.",
            _ => $"Deleted quarantined item {reply.QuarantineId} permanently.",
        };
        await stdout.WriteLineAsync(text);
        if (reply.Message is not null)
        {
            await stdout.WriteLineAsync($"note: {reply.Message}");
        }

        return ExitCodes.Clean;
    }

    private static string FormatList(IEnumerable<(string Id, string Time, long Size, string Path, string User, IReadOnlyList<string> Detections)> items)
    {
        var sb = new StringBuilder();
        foreach (var i in items)
        {
            string names = i.Detections.Count == 0 ? "manual" : string.Join(", ", i.Detections);
            sb.Append(CultureInfo.InvariantCulture, $"{i.Id}  {i.Time}  {i.Size,12:N0} B  {i.Path}  [{names}; by {i.User}]").AppendLine();
        }

        return sb.Length == 0 ? "No quarantined items." + Environment.NewLine : sb.ToString();
    }

    private static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
