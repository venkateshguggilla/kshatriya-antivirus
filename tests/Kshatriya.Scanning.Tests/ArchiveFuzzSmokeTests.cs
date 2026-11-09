using Kshatriya.Core;
using Kshatriya.Engines.Hash;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Scanning.Tests;

/// <summary>Short, deterministic mutation-fuzz run for CI. The full run lives in tools/Kshatriya.Fuzz.</summary>
public class ArchiveFuzzSmokeTests
{
    [Fact]
    public async Task Mutated_archives_never_throw_or_fail_engines()
    {
        byte[][] seeds =
        [
            ZipFactory.Create(("a.txt", "hello"u8.ToArray()), ("b/c.bin", TestData.BenignBytes(1, 1500))),
            ZipFactory.Create(("inner.zip", ZipFactory.Create(("x", TestData.BenignBytes(2, 200))))),
        ];
        var runner = new ScanRunner([HashEngine.CreateDefault()]);
        var mutator = new Mutator(7);

        for (int i = 0; i < 2000; i++)
        {
            byte[] input = mutator.Mutate(seeds[i % seeds.Length]);
            ScanItemResult result = await runner.ScanStreamAsync(new MemoryStream(input, writable: false), "fuzz.zip");
            Assert.NotEqual(ScanReason.EngineError, result.Reason);
        }
    }
}
