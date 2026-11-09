using Kshatriya.Engines.Pe;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Engines.Pe.Tests;

public class PeImageTests
{
    [Fact]
    public void Parses_synthetic_image_sections_and_imports()
    {
        byte[] pe = PeBuilder.Benign().Build();

        Assert.True(PeImage.TryParse(pe, out PeImage? image, out string? error), error);
        Assert.True(image!.Is64Bit);
        Assert.Equal(0x8664, image.Machine);
        Assert.Equal([".text", ".rdata", ".data", ".idata"], image.Sections.Select(s => s.Name));
        Assert.True(image.Sections[0].IsExecutable);
        Assert.False(image.Sections[0].IsWritable);
        Assert.Contains(new PeImport("KERNEL32.dll", "CreateFileW", null), image.Imports);
        Assert.Contains(new PeImport("USER32.dll", "MessageBoxW", null), image.Imports);
        Assert.Equal(13, image.Imports.Count);
        Assert.False(image.ImportsTruncated);
        Assert.Equal(image.Sections[0].VirtualAddress, image.EntryPointRva);
        Assert.Equal(0, image.OverlaySize);
    }

    [Fact]
    public void Measures_overlay_after_last_section()
    {
        var builder = PeBuilder.Benign();
        builder.Overlay = TestData.BenignBytes(3, 5000);

        Assert.True(PeImage.TryParse(builder.Build(), out PeImage? image, out _));
        Assert.Equal(5000, image!.OverlaySize);
        Assert.True(image.OverlayEntropy > 7.5);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(63)]
    public void Rejects_input_too_small_for_headers(int length)
    {
        Assert.False(PeImage.TryParse(new byte[length], out _, out _));
    }

    [Fact]
    public void Rejects_bad_signatures_and_offsets()
    {
        byte[] pe = PeBuilder.Benign().Build();

        byte[] noMz = (byte[])pe.Clone();
        noMz[0] = (byte)'X';
        Assert.False(PeImage.TryParse(noMz, out _, out _));

        byte[] badLfanew = (byte[])pe.Clone();
        BitConverter.GetBytes(int.MaxValue).CopyTo(badLfanew, 0x3C);
        Assert.False(PeImage.TryParse(badLfanew, out _, out _));

        byte[] negativeLfanew = (byte[])pe.Clone();
        BitConverter.GetBytes(-4).CopyTo(negativeLfanew, 0x3C);
        Assert.False(PeImage.TryParse(negativeLfanew, out _, out _));

        byte[] badMagic = (byte[])pe.Clone();
        badMagic[0x98] = 0x42;
        Assert.False(PeImage.TryParse(badMagic, out _, out _));
    }

    [Fact]
    public void Truncated_image_parses_without_throwing_and_flags_imports()
    {
        byte[] pe = PeBuilder.Benign().Build();

        for (int length = 0x40; length < pe.Length; length += 97)
        {
            bool ok = PeImage.TryParse(pe.AsSpan(0, length), out PeImage? image, out _);
            if (ok && length < pe.Length - 0x200)
            {
                Assert.True(image!.ImportsTruncated || image.Imports.Count == 0 || image.Imports.Count == 13);
            }
        }
    }

    [Fact]
    public void Huge_section_count_is_capped()
    {
        byte[] pe = PeBuilder.Benign().Build();
        BitConverter.GetBytes((ushort)0xFFFF).CopyTo(pe, 0x86);

        Assert.True(PeImage.TryParse(pe, out PeImage? image, out _));
        Assert.True(image!.Sections.Count <= PeImage.MaxSections);
    }

    [Fact]
    public void Real_system_binary_parses_when_present()
    {
        string path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        if (!File.Exists(path))
        {
            return;
        }

        Assert.True(PeImage.TryParse(File.ReadAllBytes(path), out PeImage? image, out string? error), error);
        Assert.True(image!.IsDll);
        Assert.NotEmpty(image.Imports);
        Assert.DoesNotContain(PeHeuristics.Evaluate(image), i => i.Weight >= 30);
    }

    [Theory]
    [InlineData(new byte[] { }, 0.0)]
    [InlineData(new byte[] { 7, 7, 7, 7 }, 0.0)]
    [InlineData(new byte[] { 0, 1 }, 1.0)]
    [InlineData(new byte[] { 0, 1, 2, 3 }, 2.0)]
    public void Shannon_entropy_matches_known_values(byte[] data, double expected)
    {
        Assert.Equal(expected, Entropy.Shannon(data), precision: 6);
    }
}
