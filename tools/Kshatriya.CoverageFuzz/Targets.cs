using System.Security.Cryptography;
using System.Text;
using Kshatriya.Core;
using Kshatriya.Engines.Hash;
using Kshatriya.Engines.Pe;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;
using Kshatriya.Updates;

namespace Kshatriya.CoverageFuzz;

/// <summary>
/// Fuzz targets. Each returns whether the input was accepted; expected rejections are caught inside the
/// target, so any exception that escapes is a bug.
/// </summary>
internal static class Targets
{
    public static readonly string[] Names = ["pe", "zip", "content"];

    private static readonly DateTimeOffset s_now = new(2026, 11, 9, 0, 0, 0, TimeSpan.Zero);
    private static readonly ECDsa s_key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static Func<byte[], bool> Create(string name) => name switch
    {
        "pe" => Pe,
        "zip" => CreateZip(),
        "content" => CreateContent(),
        _ => throw new ArgumentException($"Unknown target '{name}'."),
    };

    public static IEnumerable<byte[]> Seeds(string name)
    {
        switch (name)
        {
            case "pe":
                yield return PeBuilder.Benign().Build();
                yield return PeBuilder.PackedLike().Build();
                string kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
                if (File.Exists(kernel32))
                {
                    byte[] k = File.ReadAllBytes(kernel32);
                    yield return k[..Math.Min(k.Length, 256 * 1024)];
                }

                break;
            case "zip":
                byte[] inner = ZipFactory.Create(("deep/x.bin", TestData.BenignBytes(1, 300)));
                yield return ZipFactory.Create(("a.txt", "hello world"u8.ToArray()), ("dir/b.bin", TestData.BenignBytes(2, 2000)));
                yield return ZipFactory.Create(("nested.zip", inner), ("c.txt", new byte[100]));
                break;
            case "content":
                yield return ContentPackage.Create("stable", 3, s_now.AddHours(-1), s_now.AddDays(10), [("a.hashdb", Encoding.UTF8.GetBytes("# kshatriya-hashdb v1\n")), ("b.yar", Encoding.UTF8.GetBytes("rule r { condition: false }"))], s_key);
                break;
        }
    }

    // PE parsing, heuristics and ML feature extraction all read attacker-controlled headers.
    private static bool Pe(byte[] input)
    {
        if (!PeImage.TryParse(input, out PeImage? image, out _))
        {
            return false;
        }

        _ = PeHeuristics.Evaluate(image!);
        _ = PeFeatures.Extract(input, image!, null);
        return true;
    }

    // ZIP expansion through the real scan pipeline; an engine error means a parser threw.
    private static Func<byte[], bool> CreateZip()
    {
        var runner = new ScanRunner([HashEngine.CreateDefault()], new ScanOptions
        {
            Limits = new ScanLimits { MaxDegreeOfParallelism = 1, PerItemTimeout = TimeSpan.FromSeconds(10), Archives = new ArchiveLimits { MaxTotalBytes = 16 * 1024 * 1024 } },
        });

        return input =>
        {
            ScanItemResult result = runner.ScanStreamAsync(new MemoryStream(input, writable: false), "fuzz.zip").GetAwaiter().GetResult();
            return result.Reason == ScanReason.EngineError
                ? throw new InvalidOperationException($"Engine error: {result.Message}")
                : result.Reason == ScanReason.None;
        };
    }

    // Signed content packages: the container is parsed before the signature is checked. Mutations rarely
    // keep a valid signature, so this exercises the container format, not the signed manifest.
    private static Func<byte[], bool> CreateContent()
    {
        ContentKey trusted = ContentKey.FromSpki(s_key.ExportSubjectPublicKeyInfo());
        return input =>
        {
            try
            {
                _ = ContentPackage.Verify(input, [trusted], s_now);
                return true;
            }
            catch (ContentVerificationException)
            {
                return false;
            }
        };
    }
}
