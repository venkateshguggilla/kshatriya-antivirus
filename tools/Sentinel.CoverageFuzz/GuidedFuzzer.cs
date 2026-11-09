using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Trace = SharpFuzz.Common.Trace;
using Sentinel.Tests.Shared;

namespace Sentinel.CoverageFuzz;

/// <summary>
/// An in-process, AFL-style coverage-guided loop over SharpFuzz's edge-coverage map: inputs that hit a
/// new edge or a new hit-count bucket join the corpus and are mutated further.
/// </summary>
internal sealed unsafe class GuidedFuzzer
{
    private const int MapSize = 1 << 16;
    private const int MaxInputBytes = 1 << 20;
    private const int MaxCorpus = 4096;
    private static readonly TimeSpan HangLimit = TimeSpan.FromSeconds(10);

    private readonly string _name;
    private readonly Func<byte[], bool> _target;
    private readonly List<byte[]> _corpus = [];
    private readonly byte[] _virgin = new byte[MapSize];
    private readonly Random _random;
    private readonly Mutator _mutator;
    private readonly string _crashDir;
    private readonly string _corpusDir;
    private readonly byte* _map;
    private long _currentStart = -1;
    private byte[]? _current;

    public GuidedFuzzer(string name, Func<byte[], bool> target, IEnumerable<byte[]> seeds, int seed, string outDir)
    {
        _name = name;
        _target = target;
        _random = new Random(seed);
        _mutator = new Mutator(seed);
        _crashDir = Path.Combine(outDir, "crashes");
        _corpusDir = Path.Combine(outDir, "corpus", name);
        _map = (byte*)NativeMemory.AllocZeroed(MapSize);
        Trace.SharedMem = _map;

        var initial = seeds.ToList();
        if (Directory.Exists(_corpusDir))
        {
            initial.AddRange(Directory.EnumerateFiles(_corpusDir).Select(File.ReadAllBytes).Where(b => b.Length <= MaxInputBytes));
        }

        Seeds = initial;
    }

    private List<byte[]> Seeds { get; }

    /// <summary>Fuzzes for <paramref name="duration"/>; returns the number of failures.</summary>
    public int Run(TimeSpan duration)
    {
        StartWatchdog();
        int failures = 0;
        long accepted = 0;
        long executions = 0;

        foreach (byte[] seed in Seeds)
        {
            (bool interesting, bool ok, bool failed) = Execute(seed);
            executions++;
            accepted += ok ? 1 : 0;
            failures += failed ? 1 : 0;
            if (interesting || _corpus.Count == 0)
            {
                _corpus.Add(seed);
            }
        }

        int seedEdges = CoveredEdges();
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < duration)
        {
            byte[] input = NextInput();
            (bool interesting, bool ok, bool failed) = Execute(input);
            executions++;
            accepted += ok ? 1 : 0;
            failures += failed ? 1 : 0;
            if (interesting && _corpus.Count < MaxCorpus)
            {
                _corpus.Add(input);
                Save(_corpusDir, Hash(input), input);
            }
        }

        Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"[{_name}] {executions:N0} executions in {clock.Elapsed.TotalSeconds:F0}s ({executions / Math.Max(clock.Elapsed.TotalSeconds, 0.001):N0}/s), {failures} failure(s); edges {seedEdges:N0} from seeds -> {CoveredEdges():N0}; corpus {_corpus.Count:N0}; accepted {accepted:N0}"));
        return failures;
    }

    private byte[] NextInput()
    {
        // Favour recent corpus entries (they hold the newest coverage), sometimes splice two entries.
        int index = _random.Next(2) == 0 ? _corpus.Count - 1 - _random.Next(Math.Min(_corpus.Count, 16)) : _random.Next(_corpus.Count);
        byte[] parent = _corpus[index];
        if (_random.Next(8) == 0 && _corpus.Count > 1)
        {
            byte[] other = _corpus[_random.Next(_corpus.Count)];
            int cut = _random.Next(Math.Min(parent.Length, other.Length) + 1);
            parent = [.. parent.AsSpan(0, cut), .. other.AsSpan(Math.Min(cut, other.Length))];
        }

        byte[] input = _mutator.Mutate(parent);
        return input.Length > MaxInputBytes ? input[..MaxInputBytes] : input;
    }

    private (bool Interesting, bool Accepted, bool Failed) Execute(byte[] input)
    {
        NativeMemory.Clear(_map, MapSize);
        Trace.PrevLocation = 0;
        _current = input;
        Interlocked.Exchange(ref _currentStart, Stopwatch.GetTimestamp());
        bool accepted = false;
        bool failed = false;
        try
        {
            accepted = _target(input);
        }
        catch (Exception ex)
        {
            failed = true;
            string path = Save(_crashDir, $"{_name}-{Hash(input)}", input);
            Console.Error.WriteLine($"[{_name}] {ex.GetType().Name}: {ex.Message} (input saved to {path})");
        }
        finally
        {
            Interlocked.Exchange(ref _currentStart, -1);
        }

        return (failed ? false : HasNewCoverage(), accepted, failed);
    }

    /// <summary>AFL hit-count buckets; a byte position or bucket never seen before is new coverage.</summary>
    private bool HasNewCoverage()
    {
        bool found = false;
        for (int i = 0; i < MapSize; i++)
        {
            byte hits = _map[i];
            if (hits == 0)
            {
                continue;
            }

            byte bucket = hits switch
            {
                1 => 1,
                2 => 2,
                3 => 4,
                < 8 => 8,
                < 16 => 16,
                < 32 => 32,
                < 128 => 64,
                _ => 128,
            };

            if ((_virgin[i] & bucket) == 0)
            {
                _virgin[i] |= bucket;
                found = true;
            }
        }

        return found;
    }

    private int CoveredEdges() => _virgin.Count(b => b != 0);

    private void StartWatchdog()
    {
        var watchdog = new Thread(() =>
        {
            while (true)
            {
                Thread.Sleep(1000);
                long start = Interlocked.Read(ref _currentStart);
                if (start > 0 && Stopwatch.GetElapsedTime(start) > HangLimit && _current is { } input)
                {
                    string path = Save(_crashDir, $"{_name}-hang-{Hash(input)}", input);
                    Console.Error.WriteLine($"[{_name}] input ran longer than {HangLimit.TotalSeconds:F0}s (saved to {path})");
                    Environment.Exit(2);
                }
            }
        })
        { IsBackground = true, Name = "fuzz watchdog" };
        watchdog.Start();
    }

    private static string Hash(byte[] input) => Convert.ToHexStringLower(SHA256.HashData(input))[..16];

    private static string Save(string directory, string name, byte[] input)
    {
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, name + ".bin");
        File.WriteAllBytes(path, input);
        return path;
    }
}
