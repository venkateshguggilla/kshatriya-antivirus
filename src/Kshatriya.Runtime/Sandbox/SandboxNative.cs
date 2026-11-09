using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Runtime.Sandbox;

/// <summary>Owns a kernel handle (token, job, process, thread) and closes it with CloseHandle.</summary>
internal sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeKernelHandle()
        : base(ownsHandle: true)
    {
    }

    internal SafeKernelHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle() => SandboxNative.CloseHandle(handle);
}

/// <summary>Win32 surface for creating restricted, low-integrity worker processes inside a Job Object.</summary>
internal static unsafe partial class SandboxNative
{
    // Token access rights
    internal const uint TokenAssignPrimary = 0x0001;
    internal const uint TokenDuplicate = 0x0002;
    internal const uint TokenQuery = 0x0008;
    internal const uint TokenAdjustDefault = 0x0080;

    // CreateRestrictedToken flags
    internal const uint DisableMaxPrivilege = 0x1;

    // TOKEN_INFORMATION_CLASS
    internal const int TokenUser = 1;
    internal const int TokenIntegrityLevel = 25;

    internal const uint SeGroupIntegrity = 0x00000020;

    // Process creation
    internal const uint CreateSuspended = 0x00000004;
    internal const uint CreateUnicodeEnvironment = 0x00000400;
    internal const uint ExtendedStartupInfoPresent = 0x00080000;
    internal const uint DetachedProcess = 0x00000008;
    internal const uint StartfUseStdHandles = 0x00000100;

    internal const nint ProcThreadAttributeHandleList = 0x00020002;
    internal const nint ProcThreadAttributeMitigationPolicy = 0x00020007;
    internal const nint ProcThreadAttributeChildProcessPolicy = 0x0002000E;
    internal const uint ProcessCreationChildProcessRestricted = 0x01;

    // PROCESS_CREATION_MITIGATION_POLICY_* (first DWORD64)
    internal const ulong MitigationHeapTerminateAlwaysOn = 1UL << 12;
    internal const ulong MitigationBottomUpAslrAlwaysOn = 1UL << 16;
    internal const ulong MitigationHighEntropyAslrAlwaysOn = 1UL << 20;
    internal const ulong MitigationExtensionPointDisableAlwaysOn = 1UL << 32;
    internal const ulong MitigationFontDisableAlwaysOn = 1UL << 48;
    internal const ulong MitigationImageLoadNoRemoteAlwaysOn = 1UL << 52;
    internal const ulong MitigationImageLoadNoLowLabelAlwaysOn = 1UL << 56;

    // Job objects
    internal const int JobInfoBasicUiRestrictions = 4;
    internal const int JobInfoExtendedLimitInformation = 9;
    internal const uint JobObjectLimitActiveProcess = 0x00000008;
    internal const uint JobObjectLimitProcessMemory = 0x00000100;
    internal const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    internal const uint JobObjectLimitKillOnJobClose = 0x00002000;
    internal const uint JobObjectUiLimitAll = 0x000000FF;

    internal const uint WaitObject0 = 0;
    internal const uint StillActive = 259;

    // Process access
    internal const uint ProcessQueryLimitedInformation = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfo
    {
        public uint Cb;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2Count;
        public IntPtr Reserved2;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetCurrentProcess();

    /// <summary>FILE_MAP_READ: the only right a worker gets on a shared section.</summary>
    internal const uint FileMapRead = 0x0004;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, SafeKernelHandle targetProcess, out IntPtr target, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

    internal const uint HandleFlagInherit = 0x1;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(IntPtr process, uint desiredAccess, out SafeKernelHandle token);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial SafeKernelHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateRestrictedToken(
        SafeKernelHandle existingToken,
        uint flags,
        uint disableSidCount,
        SidAndAttributes* sidsToDisable,
        uint deletePrivilegeCount,
        IntPtr privilegesToDelete,
        uint restrictedSidCount,
        IntPtr sidsToRestrict,
        out SafeKernelHandle newToken);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSidToSidW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr LocalFree(IntPtr memory);

    [LibraryImport("advapi32.dll")]
    internal static partial uint GetLengthSid(IntPtr sid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetTokenInformation(SafeKernelHandle token, int informationClass, void* information, uint length);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(SafeKernelHandle token, int informationClass, void* information, uint length, out uint returnLength);

    /// <summary>GetCurrentProcessToken(): a pseudo-handle with TOKEN_QUERY access that needs no access check.</summary>
    internal static readonly IntPtr CurrentProcessTokenPseudoHandle = -4;

    [LibraryImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformationByPseudoHandle(IntPtr token, int informationClass, void* information, uint length, out uint returnLength);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true)]
    internal static partial SafeKernelHandle CreateJobObject(IntPtr attributes, IntPtr name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetInformationJobObject(SafeKernelHandle job, int infoClass, void* info, uint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AssignProcessToJobObject(SafeKernelHandle job, SafeKernelHandle process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateJobObject(SafeKernelHandle job, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateProcess(SafeKernelHandle process, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref nint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, nint attribute, void* value, nint size, IntPtr previousValue, IntPtr returnSize);

    [LibraryImport("kernel32.dll")]
    internal static partial void DeleteProcThreadAttributeList(IntPtr attributeList);

    [LibraryImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateProcessAsUser(
        SafeKernelHandle token,
        string applicationName,
        char* commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        char* environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    // Window stations and desktops (winuser.h)
    internal const uint WinstaAllAccess = 0x037F;
    internal const uint ReadControl = 0x00020000;
    internal const uint WriteOwner = 0x00080000;
    internal const uint GenericAll = 0x10000000;
    internal const uint CreateWindowStationFlagsNone = 0;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [LibraryImport("user32.dll", EntryPoint = "CreateWindowStationW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr CreateWindowStation(string name, uint flags, uint desiredAccess, SecurityAttributes* attributes);

    [LibraryImport("user32.dll", EntryPoint = "CreateDesktopW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr CreateDesktop(string name, IntPtr device, IntPtr deviceMode, uint flags, uint desiredAccess, SecurityAttributes* attributes);

    [LibraryImport("user32.dll", SetLastError = true)]
    internal static partial IntPtr GetProcessWindowStation();

    internal const int UoiName = 2;

    internal const int SeWindowObject = 7;
    internal const uint LabelSecurityInformation = 0x00000010;

    [LibraryImport("advapi32.dll")]
    internal static partial uint SetSecurityInfo(IntPtr handle, int objectType, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSecurityDescriptorSacl(IntPtr securityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool saclPresent, out IntPtr sacl, [MarshalAs(UnmanagedType.Bool)] out bool saclDefaulted);

    [LibraryImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetUserObjectInformation(IntPtr obj, int index, void* information, uint length, out uint lengthNeeded);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetProcessWindowStation(IntPtr windowStation);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseWindowStation(IntPtr windowStation);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseDesktop(IntPtr desktop);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr securityDescriptor, IntPtr size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint ResumeThread(SafeKernelHandle thread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint WaitForSingleObject(SafeKernelHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetExitCodeProcess(SafeKernelHandle process, out uint exitCode);
}
