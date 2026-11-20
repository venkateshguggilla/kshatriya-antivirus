using System.Text;
using System.Text.Json;
using Kshatriya.Posture;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;

namespace Kshatriya.Cli;

/// <summary>check, harden, lock and password (ADR 0022, ADR 0023). All go through the service.</summary>
internal static class SecurityCommands
{
    public static async Task<int> RunAsync(CliOptions options, Func<Task<ServiceClient>> connect, Stream stdin, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        if (options.Command == CliCommand.Harden && options.Action == "list")
        {
            await stdout.WriteAsync(FixList());
            return ExitCodes.Clean;
        }

        await using ServiceClient client = await connect();
        return options.Command switch
        {
            CliCommand.Check => await CheckAsync(client, options.Json, stdout, ct),
            CliCommand.Harden => await HardenAsync(client, options, stdout, stderr, ct),
            CliCommand.Lock => await LockAsync(client, options, stdin, stdout, stderr, ct),
            _ => await PasswordAsync(client, options, stdin, stdout, stderr, ct),
        };
    }

    private static async Task<int> CheckAsync(ServiceClient client, bool json, TextWriter stdout, CancellationToken ct)
    {
        PostureReplyDto reply = await client.GetPostureAsync(ct);
        PostureState worst = PostureSummary.Worst(reply.Checks.Select(ToCheck));
        if (json)
        {
            await stdout.WriteLineAsync(JsonSerializer.Serialize(reply, CliJsonContext.Default.PostureReplyDto));
        }
        else
        {
            await stdout.WriteAsync(Format(reply));
        }

        return worst switch
        {
            PostureState.Risk => ExitCodes.Detections,
            PostureState.Attention => ExitCodes.Suspicious,
            _ => ExitCodes.Clean,
        };
    }

    internal static PostureCheck ToCheck(PostureCheckDto c) =>
        new(c.Id, PostureWire.ParseArea(c.Area), PostureWire.ParseState(c.State), c.Title, c.Detail, c.Fix, c.FixApplied);

    internal static string Format(PostureReplyDto reply)
    {
        var sb = new StringBuilder();
        foreach (IGrouping<PostureArea, PostureCheck> group in reply.Checks.Select(ToCheck).GroupBy(c => c.Area))
        {
            sb.AppendLine(PostureWire.Heading(group.Key));
            foreach (PostureCheck check in group)
            {
                string mark = check.State switch
                {
                    PostureState.Ok => "  ok    ",
                    PostureState.Info => "  info  ",
                    PostureState.Attention => "  CHECK ",
                    PostureState.Risk => "  RISK  ",
                    _ => "  ?     ",
                };
                sb.Append(mark).AppendLine(check.Title);
                if (check.State is PostureState.Attention or PostureState.Risk or PostureState.Info)
                {
                    sb.Append("          ").AppendLine(check.Detail);
                }

                if (check.FixId is { } fix && check.State is not PostureState.Ok)
                {
                    sb.Append("          fix: kshatriya harden ").AppendLine(fix);
                }
                else if (check.FixApplied)
                {
                    sb.Append("          applied by Kshatriya; undo: kshatriya harden ").Append(check.FixId).AppendLine(" --undo");
                }
            }

            sb.AppendLine();
        }

        int attention = reply.Checks.Count(c => c.State is "attention" or "risk");
        sb.AppendLine(attention == 0 ? "Nothing needs your attention." : $"{attention} item(s) need your attention. Fixes need an elevated administrator.");
        return sb.ToString();
    }

    private static string FixList()
    {
        var sb = new StringBuilder("Hardening fixes (each makes a Windows protection stricter and can be undone):").AppendLine();
        foreach (string fix in new[] { Fixes.UacCredentialPrompt, Fixes.AlwaysInstallElevated, Fixes.AutoRunRemovable, Fixes.Llmnr })
        {
            sb.Append("  ").Append(fix.PadRight(28)).AppendLine(Fixes.Describe(fix));
        }

        foreach (AsrRule rule in Fixes.AsrRules)
        {
            sb.Append("  ").Append((Fixes.AsrPrefix + rule.Key).PadRight(28)).Append(rule.Name).AppendLine(" (audit first; --block to block)");
        }

        return sb.ToString();
    }

    private static async Task<int> HardenAsync(ServiceClient client, CliOptions options, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        string fix = options.Argument!;
        if (!Fixes.IsKnown(fix))
        {
            await stderr.WriteLineAsync($"error: unknown fix '{fix}'. Run 'kshatriya harden list'.");
            return ExitCodes.Usage;
        }

        OperationReplyDto reply = await client.HardenAsync(fix, options.Undo, options.Block, ct);
        return await ReportAsync(reply, stdout, stderr);
    }

    private static async Task<int> LockAsync(ServiceClient client, CliOptions options, Stream stdin, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        switch (options.Action)
        {
            case "on" or "off":
                return await ReportAsync(await client.ConfigureDeviceLockAsync(options.Action == "on", ct), stdout, stderr);
            case "unlock":
                using (var reader = new StreamReader(stdin, leaveOpen: true))
                {
                    string? password = await ReadSecretAsync(options.ReadStdin, reader, "Kshatriya password: ", stderr);
                    if (password is null)
                    {
                        return ExitCodes.Usage;
                    }

                    return await ReportAsync(await client.UnlockDeviceAsync(options.Argument!, password, ct), stdout, stderr);
                }

            default:
                DeviceLockReplyDto status = await client.GetDeviceLockAsync(ct);
                await stdout.WriteAsync(FormatLock(status));
                return ExitCodes.Clean;
        }
    }

    internal static string FormatLock(DeviceLockReplyDto status)
    {
        var sb = new StringBuilder();
        sb.Append("USB drive lock: ").AppendLine(status.State);
        sb.Append("Kshatriya password: ").AppendLine(status.PasswordSet ? "set" : "not set (kshatriya password set)");
        if (status.RetryAfterSeconds > 0)
        {
            sb.AppendLine($"Too many wrong passwords: try again in {status.RetryAfterSeconds} s.");
        }

        foreach (LockedDriveDto drive in status.Drives)
        {
            string size = drive.SizeBytes is long b ? $", {b / 1_000_000_000.0:F1} GB" : string.Empty;
            sb.AppendLine($"  {drive.State,-18} {drive.Name}{size}  [{drive.Id}]" + (drive.Message is null ? string.Empty : "  " + drive.Message));
        }

        if (status.Drives.Count == 0)
        {
            sb.AppendLine("No USB drives are locked.");
        }

        sb.AppendLine("A drive is usable for a moment before it locks: keep the USB hardening fixes on (kshatriya check).");
        return sb.ToString();
    }

    private static async Task<int> PasswordAsync(ServiceClient client, CliOptions options, Stream stdin, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        using var reader = new StreamReader(stdin, leaveOpen: true);
        string? first = await ReadSecretAsync(options.ReadStdin, reader, "New Kshatriya password (at least 8 characters): ", stderr);
        if (first is null)
        {
            return ExitCodes.Usage;
        }

        string? current;
        if (options.ReadStdin)
        {
            current = await reader.ReadLineAsync(ct);
        }
        else
        {
            string? again = await ReadSecretAsync(false, reader, "Type it again: ", stderr);
            if (again != first)
            {
                await stderr.WriteLineAsync("error: the passwords do not match.");
                return ExitCodes.Usage;
            }

            current = null;
        }

        OperationReplyDto reply = await client.SetPasswordAsync(first, string.IsNullOrEmpty(current) ? null : current, ct);
        if (!reply.Succeeded && reply.Code == "currentPasswordRequired" && !options.ReadStdin)
        {
            current = await ReadSecretAsync(false, reader, "Current Kshatriya password: ", stderr);
            if (current is null)
            {
                return ExitCodes.Usage;
            }

            reply = await client.SetPasswordAsync(first, current, ct);
        }

        return await ReportAsync(reply, stdout, stderr);
    }

    /// <summary>Reads a password: a line of standard input with --stdin, otherwise from the console without echo.</summary>
    private static async Task<string?> ReadSecretAsync(bool fromStdin, StreamReader stdin, string prompt, TextWriter stderr)
    {
        if (fromStdin)
        {
            return await stdin.ReadLineAsync();
        }

        if (Console.IsInputRedirected)
        {
            await stderr.WriteLineAsync("error: input is redirected; use --stdin to pass the password on standard input.");
            return null;
        }

        await stderr.WriteAsync(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
            }
        }

        await stderr.WriteLineAsync();
        return sb.ToString();
    }

    private static async Task<int> ReportAsync(OperationReplyDto reply, TextWriter stdout, TextWriter stderr)
    {
        if (reply.Succeeded)
        {
            await stdout.WriteLineAsync(reply.Message ?? "Done.");
            return ExitCodes.Clean;
        }

        await stderr.WriteLineAsync($"error [{reply.Code}]: {reply.Message}");
        return ExitCodes.Fatal;
    }
}

[System.Text.Json.Serialization.JsonSourceGenerationOptions(PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[System.Text.Json.Serialization.JsonSerializable(typeof(PostureReplyDto))]
internal sealed partial class CliJsonContext : System.Text.Json.Serialization.JsonSerializerContext
{
}
