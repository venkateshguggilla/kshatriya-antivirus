using System.Buffers.Binary;
using System.Text;

namespace Kshatriya.Engines.Pe;

/// <summary>One section header plus derived facts.</summary>
public sealed record PeSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawOffset,
    uint RawSize,
    uint Characteristics,
    double Entropy)
{
    public const uint MemExecute = 0x20000000;
    public const uint MemRead = 0x40000000;
    public const uint MemWrite = 0x80000000;
    public const uint CntCode = 0x00000020;

    public bool IsExecutable => (Characteristics & (MemExecute | CntCode)) != 0;

    public bool IsWritable => (Characteristics & MemWrite) != 0;

    public bool ContainsRva(uint rva) =>
        rva >= VirtualAddress && rva < VirtualAddress + Math.Max(VirtualSize, RawSize);
}

/// <summary>An imported function.</summary>
public readonly record struct PeImport(string Library, string? Function, ushort? Ordinal);

/// <summary>
/// A defensively parsed Portable Executable image. Every offset and count read from the file is
/// bounds-checked and capped; malformed input yields a parse failure, never an exception.
/// </summary>
public sealed class PeImage
{
    public const int MaxSections = 96;
    public const int MaxImportLibraries = 512;
    public const int MaxImportFunctions = 16_384;
    private const int MaxNameLength = 256;

    private PeImage()
    {
    }

    public bool Is64Bit { get; private init; }

    public ushort Machine { get; private init; }

    public ushort Characteristics { get; private init; }

    public bool IsDll => (Characteristics & 0x2000) != 0;

    public uint EntryPointRva { get; private init; }

    public uint SizeOfImage { get; private init; }

    public uint SectionAlignment { get; private init; }

    public uint FileAlignment { get; private init; }

    public ushort Subsystem { get; private init; }

    public bool IsDotNet { get; private init; }

    public bool HasCertificateTable { get; private init; }

    public IReadOnlyList<PeSection> Sections { get; private init; } = [];

    public IReadOnlyList<PeImport> Imports { get; private init; } = [];

    /// <summary>True when the import directory was present but could not be fully parsed.</summary>
    public bool ImportsTruncated { get; private init; }

    /// <summary>Bytes after the last section's raw data, excluding a trailing certificate table.</summary>
    public long OverlaySize { get; private init; }

    public double OverlayEntropy { get; private init; }

    public long FileSize { get; private init; }

    public PeSection? SectionForRva(uint rva)
    {
        foreach (PeSection s in Sections)
        {
            if (s.ContainsRva(rva))
            {
                return s;
            }
        }

        return null;
    }

    public static bool TryParse(ReadOnlySpan<byte> data, out PeImage? image, out string? error)
    {
        image = null;
        error = null;
        try
        {
            image = Parse(data, out error);
            return image is not null;
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException or OverflowException)
        {
            // Defence in depth: the parser bounds-checks explicitly, but any slip must become a parse failure.
            error = $"Malformed image ({ex.GetType().Name}).";
            image = null;
            return false;
        }
    }

    private static PeImage? Parse(ReadOnlySpan<byte> data, out string? error)
    {
        error = null;
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
        {
            error = "Missing MZ header.";
            return null;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(data[0x3C..]);
        if (peOffset < 0x40 || peOffset > data.Length - 24 || !data.Slice(peOffset, 4).SequenceEqual("PE\0\0"u8))
        {
            error = "Missing or misplaced PE signature.";
            return null;
        }

        int coff = peOffset + 4;
        ushort machine = U16(data, coff);
        ushort sectionCount = U16(data, coff + 2);
        ushort optionalSize = U16(data, coff + 16);
        ushort characteristics = U16(data, coff + 18);

        int opt = coff + 20;
        if (optionalSize < 2 || !InRange(data, opt, optionalSize))
        {
            error = "Optional header is truncated.";
            return null;
        }

        ushort magic = U16(data, opt);
        if (magic is not (0x20B or 0x10B))
        {
            error = "Unknown optional header magic.";
            return null;
        }

        bool is64 = magic == 0x20B;

        int minOptional = is64 ? 112 : 96;
        if (optionalSize < minOptional)
        {
            error = "Optional header is too small.";
            return null;
        }

        uint entryPoint = U32(data, opt + 16);
        uint sectionAlignment = U32(data, opt + 32);
        uint fileAlignment = U32(data, opt + 36);
        uint sizeOfImage = U32(data, opt + 56);
        ushort subsystem = U16(data, opt + 68);
        uint dirCount = U32(data, opt + (is64 ? 108 : 92));
        int dirs = opt + (is64 ? 112 : 96);
        int availableDirs = Math.Max(0, (optionalSize - (dirs - opt)) / 8);
        int directoryCount = (int)Math.Min(Math.Min(dirCount, 16u), (uint)availableDirs);

        static (uint Rva, uint Size) ReadDirectory(ReadOnlySpan<byte> data, int dirs, int count, int index) =>
            index < count ? (U32(data, dirs + (index * 8)), U32(data, dirs + (index * 8) + 4)) : (0u, 0u);

        int sectionTable = opt + optionalSize;
        int sections = Math.Min((int)sectionCount, MaxSections);
        var list = new List<PeSection>(sections);
        long lastRawEnd = 0;
        for (int i = 0; i < sections; i++)
        {
            int h = sectionTable + (i * 40);
            if (!InRange(data, h, 40))
            {
                break;
            }

            string name = DecodeName(data.Slice(h, 8));
            uint vsize = U32(data, h + 8);
            uint va = U32(data, h + 12);
            uint rawSize = U32(data, h + 16);
            uint rawOffset = U32(data, h + 20);
            uint flags = U32(data, h + 36);

            ReadOnlySpan<byte> raw = SafeSlice(data, rawOffset, rawSize);
            list.Add(new PeSection(name, va, vsize, rawOffset, rawSize, flags, Entropy.Shannon(raw)));
            if (rawSize > 0 && rawOffset < data.Length)
            {
                lastRawEnd = Math.Max(lastRawEnd, Math.Min((long)rawOffset + rawSize, data.Length));
            }
        }

        (uint certOffset, uint certSize) = ReadDirectory(data, dirs, directoryCount, 4); // certificate table: a file offset, not an RVA
        long overlayEnd = data.Length;
        bool hasCert = certSize > 0 && certOffset > 0 && certOffset < data.Length;
        if (hasCert && certOffset >= lastRawEnd)
        {
            overlayEnd = certOffset;
        }

        long overlaySize = lastRawEnd == 0 ? 0 : Math.Max(0, overlayEnd - lastRawEnd);
        double overlayEntropy = overlaySize > 0 ? Entropy.Shannon(data.Slice((int)lastRawEnd, (int)overlaySize)) : 0;

        var imports = new List<PeImport>();
        (uint importRva, uint importSize) = ReadDirectory(data, dirs, directoryCount, 1);
        bool truncated = importRva != 0 && importSize != 0 && !ReadImports(data, list, importRva, is64, imports);

        return new PeImage
        {
            Is64Bit = is64,
            Machine = machine,
            Characteristics = characteristics,
            EntryPointRva = entryPoint,
            SizeOfImage = sizeOfImage,
            SectionAlignment = sectionAlignment,
            FileAlignment = fileAlignment,
            Subsystem = subsystem,
            IsDotNet = ReadDirectory(data, dirs, directoryCount, 14).Size > 0,
            HasCertificateTable = hasCert,
            Sections = list,
            FileSize = data.Length,
            OverlaySize = overlaySize,
            OverlayEntropy = overlayEntropy,
            Imports = imports,
            ImportsTruncated = truncated,
        };
    }

    /// <summary>Walks the import directory. Returns false when it had to stop early on malformed data or limits.</summary>
    private static bool ReadImports(ReadOnlySpan<byte> data, IReadOnlyList<PeSection> image, uint importRva, bool is64, List<PeImport> imports)
    {
        for (int lib = 0; lib < MaxImportLibraries; lib++)
        {
            long descriptor = RvaToOffset(image, importRva + (uint)(lib * 20));
            if (descriptor < 0 || !InRange(data, descriptor, 20))
            {
                return false;
            }

            int d = (int)descriptor;
            uint originalThunk = U32(data, d);
            uint nameRva = U32(data, d + 12);
            uint firstThunk = U32(data, d + 16);
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                return true; // terminator
            }

            string? library = ReadAsciiz(data, RvaToOffset(image, nameRva));
            if (library is null)
            {
                return false;
            }

            uint thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
            int thunkSize = is64 ? 8 : 4;
            for (int t = 0; ; t++)
            {
                if (imports.Count >= MaxImportFunctions)
                {
                    return false;
                }

                long thunkOffset = RvaToOffset(image, thunkRva + (uint)(t * thunkSize));
                if (thunkOffset < 0 || !InRange(data, thunkOffset, thunkSize))
                {
                    return false;
                }

                ulong thunk = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(data[(int)thunkOffset..]) : U32(data, (int)thunkOffset);
                if (thunk == 0)
                {
                    break;
                }

                bool byOrdinal = is64 ? (thunk & 0x8000000000000000UL) != 0 : (thunk & 0x80000000UL) != 0;
                if (byOrdinal)
                {
                    imports.Add(new PeImport(library, null, (ushort)(thunk & 0xFFFF)));
                    continue;
                }

                long hintName = RvaToOffset(image, (uint)(thunk & 0x7FFFFFFF));
                string? function = hintName < 0 ? null : ReadAsciiz(data, hintName + 2);
                if (function is null)
                {
                    return false;
                }

                imports.Add(new PeImport(library, function, null));
            }
        }

        return false;
    }

    private static long RvaToOffset(IReadOnlyList<PeSection> sections, uint rva)
    {
        foreach (PeSection s in sections)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize))
            {
                long delta = (long)rva - s.VirtualAddress;
                if (delta >= s.RawSize)
                {
                    return -1; // in virtual-only (uninitialised) part of the section
                }

                return s.RawOffset + delta;
            }
        }

        return -1;
    }

    private static string? ReadAsciiz(ReadOnlySpan<byte> data, long offset)
    {
        if (offset < 0 || offset >= data.Length)
        {
            return null;
        }

        ReadOnlySpan<byte> rest = data[(int)offset..];
        int length = rest[..Math.Min(rest.Length, MaxNameLength + 1)].IndexOf((byte)0);
        if (length <= 0)
        {
            return null;
        }

        foreach (byte b in rest[..length])
        {
            if (b is < 0x20 or > 0x7E)
            {
                return null;
            }
        }

        return Encoding.ASCII.GetString(rest[..length]);
    }

    private static string DecodeName(ReadOnlySpan<byte> raw)
    {
        int end = raw.IndexOf((byte)0);
        ReadOnlySpan<byte> name = end < 0 ? raw : raw[..end];
        var sb = new StringBuilder(name.Length);
        foreach (byte b in name)
        {
            sb.Append(b is >= 0x20 and <= 0x7E ? (char)b : '?');
        }

        return sb.ToString();
    }

    private static ReadOnlySpan<byte> SafeSlice(ReadOnlySpan<byte> data, uint offset, uint size)
    {
        if (offset >= data.Length || size == 0)
        {
            return [];
        }

        long available = data.Length - (long)offset;
        return data.Slice((int)offset, (int)Math.Min(size, available));
    }

    private static bool InRange(ReadOnlySpan<byte> data, long offset, long length) =>
        offset >= 0 && length >= 0 && offset + length <= data.Length;

    private static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);

    private static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
}

/// <summary>Byte entropy helpers.</summary>
public static class Entropy
{
    /// <summary>Shannon entropy in bits per byte (0–8). Empty input yields 0.</summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (byte b in data)
        {
            counts[b]++;
        }

        double entropy = 0;
        double length = data.Length;
        foreach (int c in counts)
        {
            if (c > 0)
            {
                double p = c / length;
                entropy -= p * Math.Log2(p);
            }
        }

        return entropy;
    }
}
