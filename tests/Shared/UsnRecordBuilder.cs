using System.Buffers.Binary;
using System.Text;

namespace Kshatriya.Tests.Shared;

/// <summary>Builds synthetic NTFS change-journal records (USN_RECORD_V2 layout) for parser tests and fuzzing.</summary>
internal static class UsnRecordBuilder
{
    public static byte[] Record(ulong file, ulong parent, uint reason, uint attributes, string name, ushort majorVersion = 2)
    {
        byte[] nameBytes = Encoding.Unicode.GetBytes(name);
        int length = (60 + nameBytes.Length + 7) & ~7; // records are 8-byte aligned
        byte[] record = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(record, (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(4), majorVersion);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(8), file);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(16), parent);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(40), reason);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(52), attributes);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(56), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(58), 60);
        nameBytes.CopyTo(record, 60);
        return record;
    }

    public static byte[] Concat(params byte[][] records) => [.. records.SelectMany(r => r)];
}
