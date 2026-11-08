using System.Diagnostics;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime;
using Sentinel.Runtime.Sandbox;
using Sentinel.Scanning;

namespace Sentinel.Worker;

/// <summary>
/// Sandboxed scan worker. Started by the broker (CLI or service) inside a restricted, low-integrity
/// Job Object; talks only over its standard handles. It builds engines from the configuration it is
/// sent and analyses content it is sent. It never opens files by path.
/// </summary>
internal static class Program
{
    private const int ExitUsage = 2;
    private const int ExitInitFailed = 3;
    private const int ExitProtocol = 4;
    private const string TestCrashPath = "sentinel-test://crash";
    private const string TestHangPath = "sentinel-test://hang";

    public static async Task<int> Main(string[] args)
    {
        if (!args.Contains("--worker"))
        {
            await Console.Error.WriteLineAsync("Sentinel.Worker is started by Sentinel; it is not meant to be run directly.");
            return ExitUsage;
        }

        bool testHooks = args.Contains("--test-hooks");

        // Standard output is the protocol channel; nothing else may write to it.
        Stream input = Console.OpenStandardInput();
        Stream output = Console.OpenStandardOutput();
        Console.SetOut(Console.Error);

        try
        {
            return await RunAsync(input, output, testHooks);
        }
        catch (ProtocolException ex)
        {
            await Console.Error.WriteLineAsync($"protocol error: {ex.Message}");
            return ExitProtocol;
        }
        catch (IOException)
        {
            // The broker went away.
            return 0;
        }
    }

    private static async Task<int> RunAsync(Stream input, Stream output, bool testHooks)
    {
        WorkerInitDto init = ProtocolJson.Expect<WorkerInitDto>(await FrameIO.ReadAsync(input, new FrameLimits(64 << 20, 64 << 20)), MessageType.WorkerInit);
        string integrity = TokenInfo.CurrentIntegrityLevel();
        if (init.Protocol != ProtocolVersion.Worker)
        {
            await ReplyInitAsync(output, [], string.Empty, integrity, [], $"Worker speaks protocol {ProtocolVersion.Worker}; broker sent {init.Protocol}.");
            return ExitInitFailed;
        }

        EngineConfiguration configuration = EngineConfiguration.FromDto(init.Engines);
        EngineSet engines;
        try
        {
            engines = EngineSetup.Build(configuration);
        }
        catch (EngineSetupException ex)
        {
            await ReplyInitAsync(output, [], string.Empty, integrity, [], ex.Message);
            return ExitInitFailed;
        }

        using (engines)
        {
            var analyzer = new InProcessAnalyzer(engines.Engines, configuration.Archives, configuration.MaxScanBytes);
            await ReplyInitAsync(output, analyzer.Engines, analyzer.ConfigurationFingerprint, integrity, engines.Warnings, error: null);

            var limits = new FrameLimits((int)Math.Min(FrameIO.AbsoluteMaxFrameBytes, configuration.MaxScanBytes + (2L << 20)), 1 << 20);
            while (true)
            {
                Frame? frame = await FrameIO.ReadAsync(input, limits);
                switch (frame?.Type)
                {
                    case null:
                        return 0;
                    case MessageType.Analyze:
                        await AnalyzeAsync(analyzer, frame, output, testHooks);
                        break;
                    case MessageType.Probe:
                        await ProbeAsync(ProtocolJson.Deserialize<ProbeDto>(frame.Json), testHooks, output);
                        break;
                    default:
                        throw new ProtocolException($"Unexpected message 0x{frame.Type:X2}.");
                }
            }
        }
    }

    private static async Task AnalyzeAsync(InProcessAnalyzer analyzer, Frame frame, Stream output, bool testHooks)
    {
        AnalyzeDto header = ProtocolJson.Deserialize<AnalyzeDto>(frame.Json);
        if (header.Length != frame.Binary.Length || header.BudgetMs <= 0)
        {
            throw new ProtocolException("Analyze request has an inconsistent length or budget.");
        }

        if (testHooks)
        {
            // Lets tests exercise the broker's crash and hang handling mid-analysis.
            switch (header.DisplayPath)
            {
                case TestCrashPath:
                    Crash();
                    break;
                case TestHangPath:
                    Hang();
                    break;
            }
        }

        using MemoryStream content = frame.OpenBinary();
        TimeSpan budget = TimeSpan.FromMilliseconds(header.BudgetMs);
        using var deadline = new CancellationTokenSource(budget);
        AnalysisResult result = await analyzer.AnalyzeAsync(
            new AnalysisRequest(header.DisplayPath, header.Length, header.Sha256, content, header.Trust?.ToDomain(), budget),
            deadline.Token);

        var reply = new AnalyzeReplyDto
        {
            Id = header.Id,
            Detections = [.. result.Detections.Select(d => d.ToDto())],
            Reason = WireNames.Of(result.Reason),
            Message = result.Message,
        };
        await FrameIO.WriteAsync(output, MessageType.AnalyzeReply, ProtocolJson.Serialize(reply));
    }

    private static Task ReplyInitAsync(Stream output, IReadOnlyList<EngineInfo> engines, string fingerprint, string integrity, IReadOnlyList<string> warnings, string? error)
    {
        var reply = new WorkerInitReplyDto
        {
            Protocol = ProtocolVersion.Worker,
            Engines = [.. engines.Select(e => e.ToDto())],
            Fingerprint = fingerprint,
            IntegrityLevel = integrity,
            Warnings = [.. warnings],
            Error = error,
        };
        return FrameIO.WriteAsync(output, MessageType.WorkerInitReply, ProtocolJson.Serialize(reply));
    }

    /// <summary>Diagnostics that let tests prove the sandbox holds. Disabled unless started with --test-hooks.</summary>
    private static async Task ProbeAsync(ProbeDto probe, bool testHooks, Stream output)
    {
        (bool ok, string detail) = !testHooks ? (false, "probes-disabled") : probe.Kind switch
        {
            "integrity" => (true, TokenInfo.CurrentIntegrityLevel()),
            "write" => Try(() => File.WriteAllText(probe.Argument ?? throw new ArgumentException("path required"), "sandbox write probe")),
            "read" => Try(() => _ = File.ReadAllBytes(probe.Argument ?? throw new ArgumentException("path required"))),
            "spawn" => Try(() =>
            {
                using Process? child = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 0") { UseShellExecute = false, CreateNoWindow = true });
                child?.WaitForExit();
            }),
            "allocate" => Allocate(int.Parse(probe.Argument ?? "0", System.Globalization.CultureInfo.InvariantCulture)),
            "crash" => Crash(),
            "hang" => Hang(),
            _ => (false, "unknown-probe"),
        };

        await FrameIO.WriteAsync(output, MessageType.ProbeReply, ProtocolJson.Serialize(new ProbeReplyDto { Succeeded = ok, Detail = detail }));
    }

    private static (bool, string) Try(Action action)
    {
        try
        {
            action();
            return (true, "ok");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return (false, ex.GetType().Name);
        }
    }

    private static (bool, string) Allocate(int megabytes)
    {
        // Deliberately unhandled on failure: exceeding the job memory cap must take the worker down.
        var blocks = new List<byte[]>();
        for (int i = 0; i < megabytes; i++)
        {
            byte[] block = new byte[1 << 20];
            Array.Fill(block, (byte)1);
            blocks.Add(block);
        }

        return (true, $"allocated-{blocks.Count}");
    }

    private static (bool, string) Crash()
    {
        Environment.FailFast("Sentinel worker crash probe.");
        return (false, "unreachable");
    }

    private static (bool, string) Hang()
    {
        Thread.Sleep(Timeout.Infinite);
        return (false, "unreachable");
    }
}
