using System.Buffers.Binary;
using System.Text;

namespace Sentinel.Service.RealTime;

/// <summary>One change-journal record (version 2), reduced to what is needed to rebuild a path.</summary>
public readonly record struct UsnEntry(ulong FileReference, ulong ParentReference, uint Reason, uint Attributes, string Name);

/// <summary>Parser for the records returned by <c>FSCTL_READ_USN_JOURNAL</c>.</summary>
public static class UsnRecords
{
    public const uint ReasonFileCreate = 0x00000100;
    public const uint ReasonFileDelete = 0x00000200;
    public const uint ReasonRenameOldName = 0x00001000;
    public const uint ReasonRenameNewName = 0x00002000;
    public const uint AttributeDirectory = 0x10;
    private const int HeaderV2 = 60;

    /// <summary>
    /// Parses version 2 records (other versions are skipped). The buffer is kernel output, but it is still
    /// bounds-checked: a malformed record ends parsing instead of throwing.
    /// </summary>
    public static List<UsnEntry> Parse(ReadOnlySpan<byte> records)
    {
        var entries = new List<UsnEntry>();
        int offset = 0;
        while (records.Length - offset >= HeaderV2)
        {
            ReadOnlySpan<byte> record = records[offset..];
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(record);
            if (length < HeaderV2 || length > (uint)record.Length)
            {
                break;
            }

            if (BinaryPrimitives.ReadUInt16LittleEndian(record[4..]) == 2)
            {
                ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(record[56..]);
                ushort nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record[58..]);
                if (nameLength % 2 != 0 || nameOffset < HeaderV2 || nameOffset + nameLength > length)
                {
                    break;
                }

                entries.Add(new UsnEntry(
                    BinaryPrimitives.ReadUInt64LittleEndian(record[8..]),
                    BinaryPrimitives.ReadUInt64LittleEndian(record[16..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(record[40..]),
                    BinaryPrimitives.ReadUInt32LittleEndian(record[52..]),
                    Encoding.Unicode.GetString(record.Slice(nameOffset, nameLength))));
            }

            offset += (int)length;
        }

        return entries;
    }

    /// <summary>
    /// Whether a record names something real-time protection should scan: a file that still exists under
    /// that name, or a folder that was created or moved in (its files raise no records of their own).
    /// </summary>
    public static bool IsScannable(UsnEntry entry) =>
        (entry.Reason & (ReasonFileDelete | ReasonRenameOldName)) == 0
        && ((entry.Attributes & AttributeDirectory) == 0 || (entry.Reason & (ReasonFileCreate | ReasonRenameNewName)) != 0);
}
