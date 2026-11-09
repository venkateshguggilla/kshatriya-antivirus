using System.Buffers.Binary;
using System.Text;

namespace Kshatriya.Tests.Shared;

/// <summary>
/// Builds small, synthetic, non-functional PE32+ images for parser and heuristic tests, so no real
/// executables (benign or malicious) need to be committed. The images are never executed.
/// </summary>
internal sealed class PeBuilder
{
    public const uint Code = 0x00000020;
    public const uint InitializedData = 0x00000040;
    public const uint Execute = 0x20000000;
    public const uint Read = 0x40000000;
    public const uint Write = 0x80000000;

    private const int FileAlignment = 0x200;
    private const int SectionAlignment = 0x1000;
    private const int HeadersSize = 0x400;

    public List<(string Name, uint Characteristics, byte[] Data)> Sections { get; } = [];

    public List<(string Library, string[] Functions)> Imports { get; } = [];

    public uint? EntryPointOverride { get; set; }

    public bool IsDll { get; set; }

    public byte[] Overlay { get; set; } = [];

    public PeBuilder Section(string name, uint characteristics, byte[] data)
    {
        Sections.Add((name, characteristics, data));
        return this;
    }

    public PeBuilder Import(string library, params string[] functions)
    {
        Imports.Add((library, functions));
        return this;
    }

    /// <summary>A typical, unremarkable executable layout.</summary>
    public static PeBuilder Benign() => new PeBuilder()
        .Section(".text", Code | Execute | Read, Pattern(8192))
        .Section(".rdata", InitializedData | Read, Pattern(2048))
        .Section(".data", InitializedData | Read | Write, new byte[1024])
        .Import("KERNEL32.dll", "ExitProcess", "GetModuleHandleW", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "GetLastError", "HeapAlloc", "HeapFree", "GetProcessHeap", "Sleep", "GetCommandLineW")
        .Import("USER32.dll", "MessageBoxW");

    /// <summary>Looks like a packed binary: packer section names, writable+executable high-entropy code, minimal imports.</summary>
    public static PeBuilder PackedLike() => new PeBuilder()
        .Section("UPX0", Code | Execute | Read | Write, [])
        .Section("UPX1", Code | Execute | Read | Write, TestData.BenignBytes(99, 64 * 1024))
        .Section(".rsrc", InitializedData | Read, Pattern(1024))
        .Import("KERNEL32.DLL", "LoadLibraryA", "GetProcAddress", "VirtualProtect", "ExitProcess");

    public static byte[] Pattern(int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)(i % 16 == 0 ? 0xC3 : 0x90); // low-entropy filler
        }

        return data;
    }

    public byte[] Build()
    {
        var sections = new List<(string Name, uint Flags, byte[] Data, uint Va, uint RawOffset, uint RawSize)>();
        uint va = SectionAlignment;
        uint raw = HeadersSize;
        foreach (var (name, flags, data) in Sections)
        {
            uint rawSize = (uint)Align(data.Length, FileAlignment);
            sections.Add((name, flags, data, va, data.Length == 0 ? 0 : raw, rawSize));
            raw += rawSize;
            va += (uint)Align(Math.Max(data.Length, 1), SectionAlignment);
        }

        uint importRva = 0, importSize = 0;
        if (Imports.Count > 0)
        {
            byte[] idata = BuildImports(va, out importSize);
            importRva = va;
            uint rawSize = (uint)Align(idata.Length, FileAlignment);
            sections.Add((".idata", InitializedData | Read | Write, idata, va, raw, rawSize));
            raw += rawSize;
            va += (uint)Align(idata.Length, SectionAlignment);
        }

        uint sizeOfImage = va;
        uint entry = EntryPointOverride ?? sections.FirstOrDefault(s => (s.Flags & Execute) != 0).Va;

        var file = new byte[raw + Overlay.Length];
        Span<byte> f = file;
        f[0] = (byte)'M';
        f[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(f[0x3C..], 0x80);
        "PE\0\0"u8.CopyTo(f[0x80..]);

        int coff = 0x84;
        BinaryPrimitives.WriteUInt16LittleEndian(f[coff..], 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(coff + 2)..], (ushort)sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(coff + 16)..], 0xF0);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(coff + 18)..], (ushort)(0x0022 | (IsDll ? 0x2000 : 0)));

        int opt = coff + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(f[opt..], 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 16)..], entry);
        BinaryPrimitives.WriteUInt64LittleEndian(f[(opt + 24)..], 0x140000000UL);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 32)..], SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 36)..], FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(opt + 48)..], 6);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 56)..], sizeOfImage);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 60)..], HeadersSize);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(opt + 68)..], 3);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 108)..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 112 + 8)..], importRva);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(opt + 112 + 12)..], importSize);

        int table = opt + 0xF0;
        for (int i = 0; i < sections.Count; i++)
        {
            var s = sections[i];
            int h = table + (i * 40);
            byte[] name = Encoding.ASCII.GetBytes(s.Name);
            name.AsSpan(0, Math.Min(8, name.Length)).CopyTo(f[h..]);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(h + 8)..], (uint)Math.Max(s.Data.Length, SectionAlignment));
            BinaryPrimitives.WriteUInt32LittleEndian(f[(h + 12)..], s.Va);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(h + 16)..], s.Data.Length == 0 ? 0 : s.RawSize);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(h + 20)..], s.RawOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(h + 36)..], s.Flags);
            s.Data.CopyTo(f[(int)s.RawOffset..]);
        }

        Overlay.CopyTo(f[(int)raw..]);
        return file;
    }

    private byte[] BuildImports(uint sectionRva, out uint directorySize)
    {
        int descriptors = (Imports.Count + 1) * 20;
        directorySize = (uint)descriptors;
        var body = new MemoryStream();
        body.Write(new byte[descriptors]);

        var descriptorFields = new List<(uint Ilt, uint Name)>();
        foreach (var (library, functions) in Imports)
        {
            uint iltOffset = (uint)body.Length;
            body.Write(new byte[(functions.Length + 1) * 8]);
            var hintRvas = new List<uint>();
            foreach (string function in functions)
            {
                hintRvas.Add(sectionRva + (uint)body.Length);
                body.Write(new byte[2]);
                body.Write(Encoding.ASCII.GetBytes(function));
                body.WriteByte(0);
                if (body.Length % 2 != 0)
                {
                    body.WriteByte(0);
                }
            }

            uint nameOffset = (uint)body.Length;
            body.Write(Encoding.ASCII.GetBytes(library));
            body.WriteByte(0);

            byte[] bytes = body.GetBuffer();
            for (int i = 0; i < hintRvas.Count; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan((int)iltOffset + (i * 8)), hintRvas[i]);
            }

            descriptorFields.Add((sectionRva + iltOffset, sectionRva + nameOffset));
        }

        byte[] result = body.ToArray();
        for (int i = 0; i < descriptorFields.Count; i++)
        {
            Span<byte> d = result.AsSpan(i * 20);
            BinaryPrimitives.WriteUInt32LittleEndian(d, descriptorFields[i].Ilt);
            BinaryPrimitives.WriteUInt32LittleEndian(d[12..], descriptorFields[i].Name);
            BinaryPrimitives.WriteUInt32LittleEndian(d[16..], descriptorFields[i].Ilt);
        }

        return result;
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) / alignment * alignment;
}
