using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Posture;
using Microsoft.Win32;

namespace Kshatriya.Service.Posture;

/// <summary>Where hardening fixes are written (ADR 0022). The Windows implementation is replaced in tests.</summary>
public interface IHardeningTarget
{
    /// <summary>True when Group Policy or MDM manages this machine; fixes are then refused.</summary>
    bool IsManaged { get; }

    /// <summary>A DWORD under HKLM, or null when absent.</summary>
    int? ReadDword(string key, string name);

    void WriteDword(string key, string name, int value);

    void DeleteValue(string key, string name);

    /// <summary>The Defender ASR state of a rule (0 off, 1 block, 2 audit, 6 warn), or null when not configured.</summary>
    int? ReadAsr(string ruleId);

    void SetAsr(string ruleId, int state);

    void RemoveAsr(string ruleId);
}

/// <summary>One value as it was before Kshatriya changed it, and what Kshatriya wrote.</summary>
public sealed class SavedValue
{
    /// <summary>"registry" or "asr".</summary>
    public required string Kind { get; init; }

    public required string Key { get; init; }

    public required string Name { get; init; }

    public required bool Existed { get; init; }

    public int? Previous { get; init; }

    public required int Applied { get; set; }
}

public sealed class AppliedFix
{
    public required DateTimeOffset AppliedUtc { get; init; }

    public required List<SavedValue> Values { get; init; }
}

public sealed class HardeningState
{
    public Dictionary<string, AppliedFix> Fixes { get; init; } = new(StringComparer.Ordinal);
}

/// <summary>Outcome of applying or undoing a fix.</summary>
public sealed record HardeningResult(bool Succeeded, string Code, string Message);

/// <summary>
/// Applies and undoes hardening fixes (ADR 0022). Every fix makes a Windows control stricter; the previous
/// value is recorded first and undo restores exactly it, refusing if someone else changed the value since.
/// Authorisation and auditing are the caller's job (the pipe server).
/// </summary>
public sealed class HardeningService
{
    internal const string UacKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    internal const string InstallerPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
    internal const string ExplorerPolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    internal const string DnsClientPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

    private readonly IHardeningTarget _target;
    private readonly string _stateFile;
    private readonly bool _production;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly HardeningState _state;

    public HardeningService(IHardeningTarget target, string stateDirectory, bool production, TimeProvider time)
    {
        _target = target;
        _stateFile = Path.Combine(stateDirectory, "hardening.json");
        _production = production;
        _time = time;
        _state = Load(_stateFile);
    }

    /// <summary>Fix ids Kshatriya applied and can undo.</summary>
    public IReadOnlySet<string> Applied
    {
        get
        {
            lock (_gate)
            {
                return new HashSet<string>(_state.Fixes.Keys, StringComparer.Ordinal);
            }
        }
    }

    public HardeningResult Apply(string fixId, bool block)
    {
        if (!Fixes.IsKnown(fixId))
        {
            return new(false, "unknownFix", $"'{fixId}' is not a hardening fix.");
        }

        if (_target.IsManaged)
        {
            return new(false, "managed", "This PC's settings are managed by your organisation (Group Policy or MDM). Ask your administrator to change them.");
        }

        lock (_gate)
        {
            try
            {
                if (Fixes.FindAsr(fixId) is { } rule)
                {
                    return ApplyAsr(fixId, rule, block ? AsrState.Block : AsrState.Audit);
                }

                var changes = new List<(string Key, string Name, int Value)>();
                switch (fixId)
                {
                    case Fixes.UacCredentialPrompt:
                        changes.Add((UacKey, "ConsentPromptBehaviorAdmin", 1));
                        changes.Add((UacKey, "PromptOnSecureDesktop", 1));
                        break;
                    case Fixes.AlwaysInstallElevated:
                        changes.Add((InstallerPolicyKey, "AlwaysInstallElevated", 0));
                        break;
                    case Fixes.AutoRunRemovable:
                        int current = _target.ReadDword(ExplorerPolicyKey, "NoDriveTypeAutoRun") ?? WindowsRules.AutoRunDefault;
                        changes.Add((ExplorerPolicyKey, "NoDriveTypeAutoRun", current | WindowsRules.AutoRunRemovableBit));
                        break;
                    case Fixes.Llmnr:
                        changes.Add((DnsClientPolicyKey, "EnableMulticast", 0));
                        break;
                }

                if (_state.Fixes.ContainsKey(fixId))
                {
                    return new(true, "none", "Already applied.");
                }

                var saved = new List<SavedValue>();
                foreach ((string key, string name, int value) in changes)
                {
                    int? previous = _target.ReadDword(key, name);
                    saved.Add(new SavedValue { Kind = "registry", Key = key, Name = name, Existed = previous is not null, Previous = previous, Applied = value });
                }

                // Record first, so a crash between the writes and the save can still be undone.
                _state.Fixes[fixId] = new AppliedFix { AppliedUtc = _time.GetUtcNow(), Values = saved };
                Save();
                foreach (SavedValue value in saved)
                {
                    _target.WriteDword(value.Key, value.Name, value.Applied);
                }

                return new(true, "none", Fixes.Describe(fixId));
            }
            catch (Exception ex) when (IsExpected(ex))
            {
                return new(false, "failed", $"The change could not be made: {ex.Message}");
            }
        }
    }

    private HardeningResult ApplyAsr(string fixId, AsrRule rule, int wanted)
    {
        int current = _target.ReadAsr(rule.Id) ?? AsrState.Off;
        if (Strength(current) > Strength(wanted) || current == wanted)
        {
            return new(true, "none", current == wanted ? "Already set." : "The rule is already stricter than that; nothing was changed.");
        }

        if (_state.Fixes.TryGetValue(fixId, out AppliedFix? existing))
        {
            existing.Values[0].Applied = wanted; // audit â†’ block keeps the original previous state
        }
        else
        {
            int? previous = _target.ReadAsr(rule.Id);
            _state.Fixes[fixId] = new AppliedFix
            {
                AppliedUtc = _time.GetUtcNow(),
                Values = [new SavedValue { Kind = "asr", Key = rule.Id, Name = rule.Key, Existed = previous is not null, Previous = previous, Applied = wanted }],
            };
        }

        Save();
        _target.SetAsr(rule.Id, wanted);
        return new(true, "none", wanted == AsrState.Block
            ? $"'{rule.Name}' now blocks. Undo is available if something you need stops working."
            : $"'{rule.Name}' is in audit mode: Windows records what it would block. Switch it to block once nothing you need shows up.");
    }

    /// <summary>Off &lt; audit &lt; warn &lt; block.</summary>
    private static int Strength(int state) => state switch
    {
        AsrState.Block => 3,
        AsrState.Warn => 2,
        AsrState.Audit => 1,
        _ => 0,
    };

    public HardeningResult Undo(string fixId)
    {
        lock (_gate)
        {
            if (!_state.Fixes.TryGetValue(fixId, out AppliedFix? fix))
            {
                return new(false, "notFound", "Kshatriya did not apply this fix, so there is nothing to undo.");
            }

            try
            {
                foreach (SavedValue value in fix.Values)
                {
                    int? now = value.Kind == "asr" ? _target.ReadAsr(value.Key) : _target.ReadDword(value.Key, value.Name);
                    if (now != value.Applied)
                    {
                        return new(false, "changed", $"{value.Name} was changed by someone else since Kshatriya set it; it was left as it is.");
                    }
                }

                foreach (SavedValue value in fix.Values)
                {
                    if (value.Kind == "asr")
                    {
                        if (value.Existed)
                        {
                            _target.SetAsr(value.Key, value.Previous ?? AsrState.Off);
                        }
                        else
                        {
                            _target.RemoveAsr(value.Key);
                        }
                    }
                    else if (value.Existed)
                    {
                        _target.WriteDword(value.Key, value.Name, value.Previous!.Value);
                    }
                    else
                    {
                        _target.DeleteValue(value.Key, value.Name);
                    }
                }

                _state.Fixes.Remove(fixId);
                Save();
                return new(true, "none", "Restored the previous setting.");
            }
            catch (Exception ex) when (IsExpected(ex))
            {
                return new(false, "failed", $"The setting could not be restored: {ex.Message}");
            }
        }
    }

    private static bool IsExpected(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or ManagementException or COMException or InvalidOperationException;

    private void Save() =>
        SecureStorage.WriteProtectedFile(_stateFile, JsonSerializer.Serialize(_state, HardeningJsonContext.Default.HardeningState), _production);

    private static HardeningState Load(string file)
    {
        try
        {
            return File.Exists(file) && new FileInfo(file).Length < (1 << 20)
                ? JsonSerializer.Deserialize(File.ReadAllBytes(file), HardeningJsonContext.Default.HardeningState) ?? new HardeningState()
                : new HardeningState();
        }
        catch (JsonException)
        {
            return new HardeningState();
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, MaxDepth = 8)]
[JsonSerializable(typeof(HardeningState))]
internal sealed partial class HardeningJsonContext : JsonSerializerContext
{
}

/// <summary>Writes HKLM values and Defender ASR rules as the service (LocalSystem).</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed partial class WindowsHardeningTarget : IHardeningTarget
{
    private const string DefenderScope = @"root\Microsoft\Windows\Defender";

    public bool IsManaged
    {
        get
        {
            // Domain-joined (NetSetupDomainName) or enrolled in MDM: settings there belong to the organisation.
            if (NetGetJoinInformation(null, out IntPtr name, out int status) == 0)
            {
                _ = NetApiBufferFree(name);
                if (status == 3)
                {
                    return true;
                }
            }

            using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using RegistryKey? enrollments = machine.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments");
            return enrollments?.GetSubKeyNames().Any(id =>
            {
                using RegistryKey? e = enrollments.OpenSubKey(id);
                return e?.GetValue("EnrollmentState") is int state && state == 1 && e.GetValue("ProviderID") is string { Length: > 0 };
            }) ?? false;
        }
    }

    public int? ReadDword(string key, string name)
    {
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using RegistryKey? k = machine.OpenSubKey(key);
        return k?.GetValue(name) is int value ? value : null;
    }

    public void WriteDword(string key, string name, int value)
    {
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using RegistryKey k = machine.CreateSubKey(key, writable: true);
        k.SetValue(name, value, RegistryValueKind.DWord);
    }

    public void DeleteValue(string key, string name)
    {
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using RegistryKey? k = machine.OpenSubKey(key, writable: true);
        k?.DeleteValue(name, throwOnMissingValue: false);
    }

    public int? ReadAsr(string ruleId)
    {
        ManagementBaseObject? prefs = Wmi.First(DefenderScope, "SELECT AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference");
        if (prefs?["AttackSurfaceReductionRules_Ids"] is string[] ids && prefs["AttackSurfaceReductionRules_Actions"] is Array actions)
        {
            for (int i = 0; i < ids.Length && i < actions.Length; i++)
            {
                if (string.Equals(ids[i].Trim(), ruleId, StringComparison.OrdinalIgnoreCase))
                {
                    return Convert.ToInt32(actions.GetValue(i), CultureInfo.InvariantCulture);
                }
            }
        }

        return null;
    }

    // Same as Add-MpPreference / Remove-MpPreference. Only rule ids and actions are passed; exclusions are never touched.
    public void SetAsr(string ruleId, int state) =>
        Invoke("Add", new Dictionary<string, object>
        {
            ["AttackSurfaceReductionRules_Ids"] = new[] { ruleId },
            ["AttackSurfaceReductionRules_Actions"] = new[] { (byte)state },
        });

    public void RemoveAsr(string ruleId) =>
        Invoke("Remove", new Dictionary<string, object> { ["AttackSurfaceReductionRules_Ids"] = new[] { ruleId } });

    private static void Invoke(string method, Dictionary<string, object> arguments)
    {
        using var preferences = new ManagementClass(new ManagementScope(DefenderScope), new ManagementPath("MSFT_MpPreference"), null);
        using ManagementBaseObject input = preferences.GetMethodParameters(method);
        foreach ((string name, object value) in arguments)
        {
            input[name] = value;
        }

        using ManagementBaseObject? output = preferences.InvokeMethod(method, input, null);
        if (output?["ReturnValue"] is { } code && Convert.ToInt64(code, CultureInfo.InvariantCulture) != 0)
        {
            throw new InvalidOperationException($"Defender refused the change (code {code}). Tamper protection or an organisation policy may prevent it.");
        }
    }

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetGetJoinInformation(string? server, out IntPtr name, out int status);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);
}
