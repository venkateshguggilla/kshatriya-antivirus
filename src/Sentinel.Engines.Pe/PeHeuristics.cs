using System.Collections.Frozen;

namespace Sentinel.Engines.Pe;

/// <summary>One static indicator that contributed to a heuristic score.</summary>
public sealed record PeIndicator(string Id, int Weight, string Description);

/// <summary>
/// Static heuristics over a parsed PE image. Each indicator is common in packed or injected malware
/// but also occurs in legitimate software, so indicators only add to a score; the engine reports
/// results as <c>suspicious</c>, never as confirmed malware.
/// </summary>
public static class PeHeuristics
{
    public const double HighEntropyThreshold = 7.2;
    private const uint MinEntropySectionBytes = 4096;

    private static readonly FrozenSet<string> s_packerSections = new[]
    {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", ".themida", ".vmp0", ".vmp1", ".vmp2",
        ".MPRESS1", ".MPRESS2", ".nsp0", ".nsp1", ".perplex", "PEC2", ".yP", ".enigma1", ".enigma2", "pebundle",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<string> s_remoteThreadApis = new[]
    {
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "NtSetContextThread",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static IReadOnlyList<PeIndicator> Evaluate(PeImage image)
    {
        ArgumentNullException.ThrowIfNull(image);
        var found = new List<PeIndicator>();

        foreach (PeSection s in image.Sections)
        {
            if (s_packerSections.Contains(s.Name))
            {
                found.Add(new PeIndicator("packer-section-name", 30, $"Section name '{s.Name}' is used by a known packer or protector."));
                break;
            }
        }

        PeSection? entropic = image.Sections.FirstOrDefault(s => s.IsExecutable && s.RawSize >= MinEntropySectionBytes && s.Entropy >= HighEntropyThreshold);
        if (entropic is not null)
        {
            found.Add(new PeIndicator("high-entropy-code", 30, $"Executable section '{entropic.Name}' has entropy {entropic.Entropy:F2} bits/byte, typical of compressed or encrypted code."));
        }

        PeSection? wx = image.Sections.FirstOrDefault(s => s.IsExecutable && s.IsWritable);
        if (wx is not null)
        {
            found.Add(new PeIndicator("writable-executable-section", 20, $"Section '{wx.Name}' is both writable and executable."));
        }

        if (image.Sections.Count == 0)
        {
            found.Add(new PeIndicator("no-sections", 20, "The image declares no sections."));
        }
        else if (image.EntryPointRva != 0)
        {
            PeSection? entrySection = image.SectionForRva(image.EntryPointRva);
            if (entrySection is null)
            {
                found.Add(new PeIndicator("entry-point-outside-sections", 30, "The entry point is not inside any section."));
            }
            else if (!entrySection.IsExecutable)
            {
                found.Add(new PeIndicator("entry-point-non-executable", 20, $"The entry point is in non-executable section '{entrySection.Name}'."));
            }
            else if (image.Sections.Count > 1 && ReferenceEquals(entrySection, image.Sections[^1]) && entrySection.IsWritable)
            {
                found.Add(new PeIndicator("entry-point-last-writable-section", 10, $"The entry point is in the last, writable section '{entrySection.Name}'."));
            }
        }

        if (!image.IsDotNet)
        {
            EvaluateImports(image, found);
        }

        if (image.OverlaySize > 1024 * 1024 && image.OverlaySize > image.FileSize / 2 && image.OverlayEntropy >= HighEntropyThreshold)
        {
            found.Add(new PeIndicator("large-encrypted-overlay", 10, $"{image.OverlaySize:N0} bytes of high-entropy data are appended after the last section."));
        }

        if (image.Sections.Count > 0 && image.SectionAlignment is > 0 and <= 0x10000)
        {
            PeSection last = image.Sections.MaxBy(s => s.VirtualAddress)!;
            ulong expected = Align((ulong)last.VirtualAddress + Math.Max(last.VirtualSize, last.RawSize), image.SectionAlignment);
            if (image.SizeOfImage + (ulong)image.SectionAlignment < expected)
            {
                found.Add(new PeIndicator("size-of-image-mismatch", 10, "SizeOfImage is smaller than the mapped sections require."));
            }
        }

        return found;
    }

    private static void EvaluateImports(PeImage image, List<PeIndicator> found)
    {
        var functions = image.Imports.Where(i => i.Function is not null).Select(i => i.Function!).ToHashSet(StringComparer.Ordinal);

        if (image.Imports.Count == 0 && !image.IsDll)
        {
            found.Add(new PeIndicator("no-imports", 15, "The executable imports no functions, which is unusual for a normal program."));
        }
        else if (image.Imports.Count < 10
            && functions.Contains("GetProcAddress")
            && (functions.Contains("LoadLibraryA") || functions.Contains("LoadLibraryW") || functions.Contains("LoadLibraryExA") || functions.Contains("LoadLibraryExW")))
        {
            found.Add(new PeIndicator("dynamic-import-resolution", 15, $"Only {image.Imports.Count} imports, including LoadLibrary and GetProcAddress, suggesting APIs are resolved at run time."));
        }

        bool alloc = functions.Contains("VirtualAllocEx") || functions.Contains("NtAllocateVirtualMemory");
        bool write = functions.Contains("WriteProcessMemory") || functions.Contains("NtWriteVirtualMemory");
        bool thread = functions.Overlaps(s_remoteThreadApis);
        if (alloc && write && thread)
        {
            found.Add(new PeIndicator("process-injection-apis", 25, "Imports the combination of APIs used to inject code into other processes."));
        }

        if (image.ImportsTruncated)
        {
            found.Add(new PeIndicator("malformed-imports", 10, "The import directory is malformed or truncated."));
        }
    }

    private static ulong Align(ulong value, uint alignment) => (value + alignment - 1) / alignment * alignment;
}
