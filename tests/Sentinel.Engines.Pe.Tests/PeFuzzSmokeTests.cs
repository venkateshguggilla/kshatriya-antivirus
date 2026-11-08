using Sentinel.Engines.Pe;
using Sentinel.Tests.Shared;

namespace Sentinel.Engines.Pe.Tests;

/// <summary>Short, deterministic mutation-fuzz run for CI. The full run lives in tools/Sentinel.Fuzz.</summary>
public class PeFuzzSmokeTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Mutated_images_never_throw(int seed)
    {
        byte[][] seeds = [PeBuilder.Benign().Build(), PeBuilder.PackedLike().Build()];
        var mutator = new Mutator(seed);

        for (int i = 0; i < 5000; i++)
        {
            byte[] input = mutator.Mutate(seeds[i % seeds.Length]);
            if (PeImage.TryParse(input, out PeImage? image, out _))
            {
                _ = PeHeuristics.Evaluate(image!);
            }
        }
    }
}
