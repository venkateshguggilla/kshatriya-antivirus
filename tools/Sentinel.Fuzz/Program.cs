// Mutation fuzz harness for Sentinel parsers.
//   dotnet run -c Release --project tools/Sentinel.Fuzz -- <pe|zip|hashdb|frame|report|content|all> [iterations] [seed] [crashDir]
// Any exception escaping a parser counts as a failure; the offending input is saved to crashDir.
// This is unguided mutation fuzzing; coverage-guided fuzzing (SharpFuzz + libFuzzer) is future work.

using System.Diagnostics;
using System.Globalization;
using System.Text;
using Sentinel.Core;
using Sentinel.Engines.Hash;
using Sentinel.Engines.Pe;
using Sentinel.Protocol;
using Sentinel.Scanning;
using Sentinel.Tests.Shared;
using Sentinel.Updates;

string target = args.Length > 0 ? args[0] : "all";
long iterations = args.Length > 1 ? long.Parse(args[1], CultureInfo.InvariantCulture) : 1_000_000;
int seed = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 20261108;
string crashDir = args.Length > 3 ? args[3] : Path.Combine(Path.GetTempPath(), "sentinel-fuzz-crashes");

int failures = 0;
foreach (string t in target == "all" ? new[] { "pe", "zip", "hashdb", "frame", "report", "content" } : [target])
{
    failures += t switch
    {
        "pe" => FuzzPe(iterations, seed, crashDir),
        "zip" => await FuzzZipAsync(iterations, seed, crashDir),
        "hashdb" => FuzzHashDb(iterations, seed, crashDir),
        "frame" => await FuzzFramesAsync(iterations, seed, crashDir),
        "report" => FuzzReport(iterations, seed, crashDir),
        "content" => FuzzContent(iterations, seed, crashDir),
        _ => throw new ArgumentException($"Unknown target '{t}'."),
    };
}

return failures == 0 ? 0 : 1;

static int FuzzPe(long iterations, int seed, string crashDir)
{
    var seeds = new List<byte[]> { PeBuilder.Benign().Build(), PeBuilder.PackedLike().Build() };
    string kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
    if (File.Exists(kernel32))
    {
        byte[] k = File.ReadAllBytes(kernel32);
        seeds.Add(k[..Math.Min(k.Length, 256 * 1024)]);
    }

    var mutator = new Mutator(seed);
    long parsed = 0;
    int failures = 0;
    var sw = Stopwatch.StartNew();
    for (long i = 0; i < iterations; i++)
    {
        byte[] input = mutator.Mutate(seeds[(int)(i % seeds.Count)]);
        try
        {
            if (PeImage.TryParse(input, out PeImage? image, out _))
            {
                parsed++;
                _ = PeHeuristics.Evaluate(image!);
            }
        }
        catch (Exception ex)
        {
            failures += Save(crashDir, "pe", i, input, ex);
        }
    }

    Report("pe", iterations, failures, sw.Elapsed, $"parsed {parsed:N0}");
    return failures;
}

static async Task<int> FuzzZipAsync(long iterations, int seed, string crashDir)
{
    byte[] inner = ZipFactory.Create(("deep/x.bin", TestData.BenignBytes(1, 300)));
    var seeds = new List<byte[]>
    {
        ZipFactory.Create(("a.txt", "hello world"u8.ToArray()), ("dir/b.bin", TestData.BenignBytes(2, 2000))),
        ZipFactory.Create(("nested.zip", inner), ("c.txt", new byte[100])),
    };

    var runner = new ScanRunner([HashEngine.CreateDefault()], new ScanOptions
    {
        Limits = new ScanLimits { PerItemTimeout = TimeSpan.FromSeconds(10), Archives = new ArchiveLimits { MaxTotalBytes = 16 * 1024 * 1024 } },
    });

    var mutator = new Mutator(seed);
    var statuses = new Dictionary<string, long>();
    int failures = 0;
    var sw = Stopwatch.StartNew();
    for (long i = 0; i < iterations; i++)
    {
        byte[] input = mutator.Mutate(seeds[(int)(i % seeds.Count)]);
        try
        {
            ScanItemResult result = await runner.ScanStreamAsync(new MemoryStream(input, writable: false), "fuzz.zip");
            string key = $"{result.Status}/{result.Reason}";
            statuses[key] = statuses.GetValueOrDefault(key) + 1;
            if (result.Reason == ScanReason.EngineError)
            {
                failures += Save(crashDir, "zip", i, input, new InvalidOperationException(result.Message));
            }
        }
        catch (Exception ex)
        {
            failures += Save(crashDir, "zip", i, input, ex);
        }
    }

    Report("zip", iterations, failures, sw.Elapsed, string.Join(", ", statuses.OrderByDescending(p => p.Value).Select(p => $"{p.Key}={p.Value:N0}")));
    return failures;
}

static int FuzzHashDb(long iterations, int seed, string crashDir)
{
    byte[] seedText = Encoding.UTF8.GetBytes($"# sentinel-hashdb v1\n# c\nsha256:{new string('a', 64)} Family.One malware\nsha256:{new string('b', 64)} T test\n");
    var mutator = new Mutator(seed);
    long accepted = 0;
    int failures = 0;
    var sw = Stopwatch.StartNew();
    for (long i = 0; i < iterations; i++)
    {
        byte[] input = mutator.Mutate(seedText);
        try
        {
            _ = HashSignatureDatabase.Parse(Encoding.UTF8.GetString(input));
            accepted++;
        }
        catch (FormatException)
        {
            // Expected: malformed databases are rejected.
        }
        catch (Exception ex)
        {
            failures += Save(crashDir, "hashdb", i, input, ex);
        }
    }

    Report("hashdb", iterations, failures, sw.Elapsed, $"accepted {accepted:N0}");
    return failures;
}

// IPC input from an untrusted peer: frame decoding plus strict DTO decoding and wire-name mapping.
// The only acceptable failure is ProtocolException.
static async Task<int> FuzzFramesAsync(long iterations, int seed, string crashDir)
{
    var detection = new DetectionDto { Engine = "hash", Name = "N", Category = "test", Confidence = "high", Location = "a>b" };
    var messages = new (byte Type, byte[] Json, byte[] Binary)[]
    {
        (MessageType.Hello, ProtocolJson.Serialize(new HelloDto { Protocol = 1, Client = "c" }), []),
        (MessageType.Scan, ProtocolJson.Serialize(new ScanRequestDto { Paths = [@"C:\x", @"D:\y"], IncludeClean = true, Action = "quarantine" }), []),
        (MessageType.QuarantineRestore, ProtocolJson.Serialize(new QuarantineRestoreDto { Id = new string('a', 32), TargetPath = @"C:\t" }), []),
        (MessageType.ExclusionsChange, ProtocolJson.Serialize(new ExclusionChangeDto { Operation = "add", Value = @"C:\tools" }), []),
        (MessageType.AuditQuery, ProtocolJson.Serialize(new AuditQueryDto { Max = 5 }), []),
        (MessageType.Analyze, ProtocolJson.Serialize(new AnalyzeDto { Id = 7, DisplayPath = "p", Length = 4, Sha256 = new string('a', 64), BudgetMs = 1000, Trust = new TrustDto { Status = "valid", Source = "catalog", Signer = "S" } }), [1, 2, 3, 4]),
        (MessageType.AnalyzeReply, ProtocolJson.Serialize(new AnalyzeReplyDto { Id = 7, Detections = [detection], Reason = "archiveLimit", Message = "m" }), []),
        (MessageType.ScanProgress, ProtocolJson.Serialize(new ScanProgressDto { ItemsCompleted = 1, Detected = 0, BytesScanned = 9 }), []),
        (MessageType.Error, ProtocolJson.Serialize(new ErrorDto { Code = "busy", Message = "m" }), []),
    };

    var seeds = new List<byte[]>();
    foreach (var (type, json, binary) in messages)
    {
        using var buffer = new MemoryStream();
        await FrameIO.WriteAsync(buffer, type, json, new MemoryStream(binary), binary.Length);
        seeds.Add(buffer.ToArray());
    }

    var mutator = new Mutator(seed);
    var limits = new FrameLimits(1 << 20, 1 << 16);
    long decoded = 0;
    int failures = 0;
    var sw = Stopwatch.StartNew();
    for (long i = 0; i < iterations; i++)
    {
        byte[] input = mutator.Mutate(seeds[(int)(i % seeds.Count)]);
        try
        {
            using var stream = new MemoryStream(input, writable: false);
            while (await FrameIO.ReadAsync(stream, limits) is { } frame)
            {
                DecodeFrame(frame);
                decoded++;
            }
        }
        catch (ProtocolException)
        {
            // Expected: malformed input is rejected and the connection would be dropped.
        }
        catch (Exception ex)
        {
            failures += Save(crashDir, "frame", i, input, ex);
        }
    }

    Report("frame", iterations, failures, sw.Elapsed, $"decoded {decoded:N0}");
    return failures;

    static void DecodeFrame(Frame frame)
    {
        switch (frame.Type)
        {
            case MessageType.Hello:
                _ = ProtocolJson.Deserialize<HelloDto>(frame.Json);
                break;
            case MessageType.Scan:
                _ = ProtocolJson.Deserialize<ScanRequestDto>(frame.Json);
                break;
            case MessageType.QuarantineAdd:
                _ = ProtocolJson.Deserialize<QuarantineAddDto>(frame.Json);
                break;
            case MessageType.QuarantineRestore:
                _ = ProtocolJson.Deserialize<QuarantineRestoreDto>(frame.Json);
                break;
            case MessageType.QuarantineDelete:
                _ = ProtocolJson.Deserialize<QuarantineDeleteDto>(frame.Json);
                break;
            case MessageType.ExclusionsChange:
                _ = ProtocolJson.Deserialize<ExclusionChangeDto>(frame.Json);
                break;
            case MessageType.AuditQuery:
                _ = ProtocolJson.Deserialize<AuditQueryDto>(frame.Json);
                break;
            case MessageType.Analyze:
                _ = ProtocolJson.Deserialize<AnalyzeDto>(frame.Json).Trust?.ToDomain();
                break;
            case MessageType.AnalyzeReply:
                AnalyzeReplyDto reply = ProtocolJson.Deserialize<AnalyzeReplyDto>(frame.Json);
                _ = DtoMapping.ParseReason(reply.Reason);
                _ = reply.Detections.Select(d => d.ToDomain()).ToList();
                break;
            case MessageType.ScanProgress:
                _ = ProtocolJson.Deserialize<ScanProgressDto>(frame.Json);
                break;
            default:
                _ = ProtocolJson.Deserialize<ErrorDto>(frame.Json);
                break;
        }
    }
}

// Reports read back from the service (or from disk). The only acceptable failure is FormatException.
// Signed content packages: the only acceptable failure is ContentVerificationException.
static int FuzzContent(long iterations, int seed, string crashDir)
{
    using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
    ContentKey trusted = ContentKey.FromSpki(key.ExportSubjectPublicKeyInfo());
    var now = new DateTimeOffset(2026, 11, 8, 0, 0, 0, TimeSpan.Zero);
    byte[] seedPackage = ContentPackage.Create("stable", 3, now.AddHours(-1), now.AddDays(10), [("a.hashdb", Encoding.UTF8.GetBytes("# sentinel-hashdb v1\n")), ("b.yar", Encoding.UTF8.GetBytes("rule r { condition: false }"))], key);
    var mutator = new Mutator(seed);
    long accepted = 0;
    int failures = 0;
    var sw = Stopwatch.StartNew();
    for (long i = 0; i < iterations; i++)
    {
        byte[] input = mutator.Mutate(seedPackage);
        try
        {
            _ = ContentPackage.Verify(input, [trusted], now);
            accepted++;
        }
        catch (ContentVerificationException)
        {
            // Expected: refused.
        }
        catch (Exception ex)
        {
            failures += Save(crashDir, "content", i, input, ex);
        }
    }

    Report("content", iterations, failures, sw.Elapsed, $"accepted {accepted:N0}");
    return failures;
}

static int FuzzReport(long iterations, int seed, string crashDir)
{
    var report = new ScanReport
    {
        Targets = [@"C:\scan"],
        StartedUtc = new DateTimeOffset(2026, 11, 8, 1, 2, 3, TimeSpan.Zero),
        FinishedUtc = new DateTimeOffset(2026, 11, 8, 1, 2, 4, TimeSpan.Zero),
        Engines = [new EngineInfo("hash", "1.0.0", "1-abc")],
        Summary = new ScanSummary { ItemsSeen = 4, FilesScanned = 2, Detected = 2, Skipped = 1, NotScanned = 1, BytesScanned = 10, Quarantined = 1, QuarantineFailed = 1 },
        Items =
        [
            new ScanItemResult
            {
                Path = @"C:\scan\a.zip",
                Kind = ScanItemKind.File,
                Status = ScanStatus.Detected,
                SizeBytes = 10,
                Sha256 = new string('b', 64),
                Trust = new FileTrust(TrustStatus.Valid, TrustSource.Embedded, "Signer"),
                Detections = [new Detection("hash", "T", DetectionCategory.TestFile, DetectionConfidence.High, "d") { Location = "x/y" }],
                Action = ItemAction.Quarantined(new string('c', 32)),
            },
            new ScanItemResult
            {
                Path = @"C:\scan\b.exe",
                Kind = ScanItemKind.File,
                Status = ScanStatus.Detected,
                Detections = [new Detection("hash", "U", DetectionCategory.Malware, DetectionConfidence.High)],
                Action = ItemAction.Failed(ActionFailure.InUse, "running"),
            },
            ScanItemResult.Skip(@"C:\scan\tools", ScanItemKind.Directory, ScanReason.Excluded),
            ScanItemResult.Fail(@"C:\scan\locked.bin", ScanItemKind.File, ScanReason.Locked, "busy"),
        ],
    };
    byte[] seedText = Encoding.UTF8.GetBytes(ScanReportJson.Write(report, "0.0.0"));
    var mutator = new Mutator(seed);
    long accepted = 0;
    int failures = 0;
    var sw = Stopwatch.StartNew();
    for (long i = 0; i < iterations; i++)
    {
        byte[] input = mutator.Mutate(seedText);
        try
        {
            _ = ScanReportJson.Read(Encoding.UTF8.GetString(input));
            accepted++;
        }
        catch (FormatException)
        {
            // Expected.
        }
        catch (Exception ex)
        {
            failures += Save(crashDir, "report", i, input, ex);
        }
    }

    Report("report", iterations, failures, sw.Elapsed, $"accepted {accepted:N0}");
    return failures;
}

static int Save(string crashDir, string target, long iteration, byte[] input, Exception ex)
{
    Directory.CreateDirectory(crashDir);
    string path = Path.Combine(crashDir, $"{target}-{iteration}.bin");
    File.WriteAllBytes(path, input);
    Console.Error.WriteLine($"[{target}] iteration {iteration}: {ex.GetType().Name}: {ex.Message} (input saved to {path})");
    return 1;
}

static void Report(string target, long iterations, int failures, TimeSpan elapsed, string detail) =>
    Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
        $"[{target}] {iterations:N0} iterations in {elapsed.TotalSeconds:F1}s, {failures} failure(s); {detail}"));
