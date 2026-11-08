using System.Runtime.InteropServices;

namespace Sentinel.App.Services;

/// <summary>Overall Windows antivirus health as reported by Windows Security Center (read-only).</summary>
public enum AntivirusHealth
{
    Good,
    NotMonitored,
    Poor,
    Snoozed,
    Unknown,
}

/// <summary>
/// Reads the antivirus health that Windows Security Center reports for the registered antivirus
/// products (normally Microsoft Defender). Sentinel only reads this to remind people to keep their
/// primary protection on; it never changes it.
/// </summary>
public static partial class SecurityCenter
{
    private const int WscSecurityProviderAntivirus = 0x0004;

    public static AntivirusHealth GetAntivirusHealth()
    {
        try
        {
            int hr = WscGetSecurityProviderHealth(WscSecurityProviderAntivirus, out int health);
            if (hr != 0)
            {
                return AntivirusHealth.Unknown;
            }

            return health switch
            {
                0 => AntivirusHealth.Good,
                1 => AntivirusHealth.NotMonitored,
                2 => AntivirusHealth.Poor,
                3 => AntivirusHealth.Snoozed,
                _ => AntivirusHealth.Unknown,
            };
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Windows Server editions do not ship Security Center.
            return AntivirusHealth.Unknown;
        }
    }

    public static string Describe(AntivirusHealth health) => health switch
    {
        AntivirusHealth.Good => "Windows antivirus protection is on (Microsoft Defender or another registered antivirus).",
        AntivirusHealth.NotMonitored => "Windows Security Center is not monitoring antivirus protection on this device.",
        AntivirusHealth.Poor => "Windows reports that antivirus protection is OFF or out of date. Turn Microsoft Defender back on in Windows Security. Sentinel is not a replacement.",
        AntivirusHealth.Snoozed => "Windows antivirus protection is snoozed. Turn it back on in Windows Security.",
        _ => "Windows antivirus status could not be read.",
    };

    [LibraryImport("wscapi.dll")]
    private static partial int WscGetSecurityProviderHealth(int providers, out int health);
}
