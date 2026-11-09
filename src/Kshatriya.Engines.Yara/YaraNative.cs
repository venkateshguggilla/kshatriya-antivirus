using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Kshatriya.Engines.Yara;

/// <summary>P/Invoke surface for the YARA-X C API (yara_x.h, v1.22). x64 layouts only.</summary>
internal static unsafe partial class YaraNative
{
    internal const string Library = "yara_x_capi";

    internal const int Success = 0;
    internal const int SyntaxError = 1;
    internal const int ScanTimeout = 4;

    internal const uint DisableIncludes = 32;

    internal const int MetaI64 = 0;
    internal const int MetaF64 = 1;
    internal const int MetaBoolean = 2;
    internal const int MetaString = 3;
    internal const int MetaBytes = 4;

    [StructLayout(LayoutKind.Explicit)]
    internal struct Metadata
    {
        [FieldOffset(0)]
        public byte* Identifier;

        [FieldOffset(8)]
        public int ValueType;

        [FieldOffset(16)]
        public long I64;

        [FieldOffset(16)]
        public double F64;

        [FieldOffset(16)]
        public byte Boolean;

        [FieldOffset(16)]
        public byte* String;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Buffer
    {
        public byte* Data;
        public nuint Length;
    }

    [LibraryImport(Library, EntryPoint = "yrx_last_error")]
    internal static partial byte* LastError();

    [LibraryImport(Library, EntryPoint = "yrx_compiler_create")]
    internal static partial int CompilerCreate(uint flags, out IntPtr compiler);

    [LibraryImport(Library, EntryPoint = "yrx_compiler_destroy")]
    internal static partial void CompilerDestroy(IntPtr compiler);

    [LibraryImport(Library, EntryPoint = "yrx_compiler_add_source_with_origin", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int CompilerAddSource(IntPtr compiler, string source, string origin);

    [LibraryImport(Library, EntryPoint = "yrx_compiler_build")]
    internal static partial IntPtr CompilerBuild(IntPtr compiler);

    [LibraryImport(Library, EntryPoint = "yrx_rules_count")]
    internal static partial int RulesCount(IntPtr rules);

    [LibraryImport(Library, EntryPoint = "yrx_rules_destroy")]
    internal static partial void RulesDestroy(IntPtr rules);

    [LibraryImport(Library, EntryPoint = "yrx_scanner_create")]
    internal static partial int ScannerCreate(IntPtr rules, out IntPtr scanner);

    [LibraryImport(Library, EntryPoint = "yrx_scanner_destroy")]
    internal static partial void ScannerDestroy(IntPtr scanner);

    [LibraryImport(Library, EntryPoint = "yrx_scanner_set_timeout")]
    internal static partial int ScannerSetTimeout(IntPtr scanner, ulong seconds);

    [LibraryImport(Library, EntryPoint = "yrx_scanner_on_matching_rule")]
    internal static partial int ScannerOnMatchingRule(IntPtr scanner, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> callback, IntPtr userData);

    [LibraryImport(Library, EntryPoint = "yrx_scanner_scan")]
    internal static partial int ScannerScan(IntPtr scanner, byte* data, nuint length);

    [LibraryImport(Library, EntryPoint = "yrx_rule_identifier")]
    internal static partial int RuleIdentifier(IntPtr rule, out byte* identifier, out nuint length);

    [LibraryImport(Library, EntryPoint = "yrx_rule_namespace")]
    internal static partial int RuleNamespace(IntPtr rule, out byte* ns, out nuint length);

    [LibraryImport(Library, EntryPoint = "yrx_rule_iter_metadata")]
    internal static partial int RuleIterMetadata(IntPtr rule, delegate* unmanaged[Cdecl]<Metadata*, IntPtr, void> callback, IntPtr userData);

    internal static string? LastErrorMessage()
    {
        byte* message = LastError();
        return message is null ? null : Marshal.PtrToStringUTF8((IntPtr)message);
    }

    internal static string Utf8(byte* data, nuint length) =>
        data is null || length == 0 ? string.Empty : System.Text.Encoding.UTF8.GetString(data, checked((int)length));

    [SkipLocalsInit]
    internal static string? Utf8Z(byte* data) => data is null ? null : Marshal.PtrToStringUTF8((IntPtr)data);
}
