// Mutation fuzz harness for Sentinel parsers.
//   dotnet run -c Release --project tools/Sentinel.Fuzz -- <pe|zip|hashdb|all> [iterations] [seed] [crashDir]
// Any exception escaping a parser counts as a failure; the offending input is saved to crashDir.
// This is unguided mutation fuzzing; coverage-guided fuzzing (SharpFuzz + libFuzzer) is future work.

using System.Diagnostics;
using System.Globalization;
using System.Text;
using Sentinel.Core;
using Sentinel.Engines.Hash;
using Sentinel.Engines.Pe;
using Sentinel.Scanning;
using Sentinel.Tests.Shared;

string target = args.Length > 0 ? args[0] : "all";
long iterations = args.Length > 1 ? long.Parse(args[1], CultureInfo.InvariantCulture) : 1_000_000;
int seed = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 20261108;
string crashDir = args.Length > 3 ? args[3] : Path.Combine(Path.GetTempPath(), "sentinel-fuzz-crashes");

int failures = 0;
foreach (string t in target == "all" ? new[] { "pe", "zip", "hashdb" } : [target])
{
    failures += t switch
    {
        "pe" => FuzzPe(iterations, seed, crashDir),
        "zip" => await FuzzZipAsync(iterations, seed, crashDir),
        "hashdb" => FuzzHashDb(iterations, seed, crashDir),
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
