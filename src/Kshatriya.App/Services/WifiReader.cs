using System.Runtime.InteropServices;
using Kshatriya.Posture;

namespace Kshatriya.App.Services;

/// <summary>
/// Reads the security of the connected Wi-Fi network with the Native Wifi API (ADR 0022). Runs in the app, as
/// the user: Windows answers only with the user's location consent, which a service cannot have. Read-only.
/// </summary>
internal static partial class WifiReader
{
    private const uint WlanIntfOpcodeCurrentConnection = 7;
    private const int ConnectedState = 1; // wlan_interface_state_connected

    /// <summary>The connected network's security, or null (no Wi-Fi, not connected, or no location consent).</summary>
    public static WifiSnapshot? Read()
    {
        try
        {
            if (WlanOpenHandle(2, IntPtr.Zero, out _, out IntPtr client) != 0)
            {
                return null;
            }

            try
            {
                return ReadConnected(client);
            }
            finally
            {
                _ = WlanCloseHandle(client, IntPtr.Zero);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null; // no WLAN service on this machine
        }
    }

    private static unsafe WifiSnapshot? ReadConnected(IntPtr client)
    {
        if (WlanEnumInterfaces(client, IntPtr.Zero, out IntPtr list) != 0)
        {
            return null;
        }

        try
        {
            // WLAN_INTERFACE_INFO_LIST: dwNumberOfItems, dwIndex, then WLAN_INTERFACE_INFO[] (GUID + WCHAR[256] + state = 532 bytes).
            int count = Marshal.ReadInt32(list);
            for (int i = 0; i < count; i++)
            {
                IntPtr info = list + 8 + (i * 532);
                Guid id = Marshal.PtrToStructure<Guid>(info);
                int state = Marshal.ReadInt32(info + 16 + 512);
                if (state != ConnectedState)
                {
                    continue;
                }

                if (WlanQueryInterface(client, &id, WlanIntfOpcodeCurrentConnection, IntPtr.Zero, out uint size, out IntPtr data, out _) != 0)
                {
                    continue; // ERROR_ACCESS_DENIED without location consent
                }

                try
                {
                    if (size < 604)
                    {
                        continue;
                    }

                    // WLAN_CONNECTION_ATTRIBUTES: association attributes at 520 (SSID length, SSID bytes),
                    // security attributes at 588 (bSecurityEnabled, bOneXEnabled, auth algorithm, cipher algorithm).
                    int ssidLength = Math.Clamp(Marshal.ReadInt32(data + 520), 0, 32);
                    byte[] ssid = new byte[ssidLength];
                    Marshal.Copy(data + 524, ssid, 0, ssidLength);
                    bool secured = Marshal.ReadInt32(data + 588) != 0;
                    int auth = Marshal.ReadInt32(data + 596);
                    int cipher = Marshal.ReadInt32(data + 600);
                    string name = System.Text.Encoding.UTF8.GetString(ssid);
                    return new WifiSnapshot(name.Length == 0 ? "Wi-Fi" : name, Authentication(auth, secured), Cipher(cipher));
                }
                finally
                {
                    WlanFreeMemory(data);
                }
            }

            return null;
        }
        finally
        {
            WlanFreeMemory(list);
        }
    }

    /// <summary>DOT11_AUTH_ALGORITHM names as NetworkRules.Wifi expects them.</summary>
    internal static string Authentication(int algorithm, bool secured) => algorithm switch
    {
        1 => secured ? "WEP" : "Open", // open authentication with encryption is WEP
        2 => "SharedKey",
        3 => "WPA",
        4 => "WPAPSK",
        6 => "WPA2",
        7 => "WPA2PSK",
        8 or 11 => "WPA3",
        9 => "WPA3SAE",
        10 => "OWE",
        _ => "Unknown",
    };

    /// <summary>DOT11_CIPHER_ALGORITHM names.</summary>
    internal static string Cipher(int algorithm) => algorithm switch
    {
        0 => "None",
        1 or 5 or 0x101 => "WEP",
        2 => "TKIP",
        4 or 10 => "CCMP",
        8 or 9 => "GCMP",
        _ => "Unknown",
    };

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [LibraryImport("wlanapi.dll")]
    private static unsafe partial uint WlanQueryInterface(IntPtr clientHandle, Guid* interfaceGuid, uint opCode, IntPtr reserved, out uint dataSize, out IntPtr data, out uint opcodeValueType);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(IntPtr memory);
}
