using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Tests.Shared;

/// <summary>Harmless test content. Nothing here is malware.</summary>
internal static class TestData
{
    /// <summary>
    /// The standard EICAR test string, assembled at runtime from fragments so that no source file
    /// or compiled binary in this repository contains it contiguously (which would make Microsoft
    /// Defender quarantine our own build output). We never add Defender exclusions.
    /// </summary>
    public static byte[] EicarBytes()
    {
        string[] fragments = [@"X5O!P%@AP[4\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!", "$H+H*"];
        return Encoding.ASCII.GetBytes(string.Concat(fragments));
    }

    /// <summary>Deterministic pseudo-random benign bytes.</summary>
    public static byte[] BenignBytes(int seed, int length)
    {
        var bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    public static string Sha256Hex(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public static string HashDb(params (string Sha256, string Name, string Category)[] entries)
    {
        var sb = new StringBuilder("# sentinel-hashdb v1\n");
        foreach (var (sha, name, category) in entries)
        {
            sb.Append("sha256:").Append(sha).Append(' ').Append(name).Append(' ').Append(category).Append('\n');
        }

        return sb.ToString();
    }
}

/// <summary>A unique temporary directory, removed on dispose without ever following links.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string relative, byte[] content)
    {
        string full = System.IO.Path.Combine(Path, relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        System.IO.File.WriteAllBytes(full, content);
        return full;
    }

    public string Dir(string relative) => Directory.CreateDirectory(System.IO.Path.Combine(Path, relative)).FullName;

    /// <summary>Creates a directory junction (no admin rights needed). Returns false if unsupported.</summary>
    public static bool TryCreateJunction(string link, string target)
    {
        var psi = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("/c");
        psi.ArgumentList.Add("mklink");
        psi.ArgumentList.Add("/J");
        psi.ArgumentList.Add(link);
        psi.ArgumentList.Add(target);
        using Process p = Process.Start(psi)!;
        p.WaitForExit(10_000);
        return p.ExitCode == 0 && Directory.Exists(link);
    }

    public void Dispose()
    {
        try
        {
            SafeDelete(new DirectoryInfo(Path));
        }
        catch (IOException)
        {
            // Best effort; temp folder cleanup must never fail a test.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void SafeDelete(DirectoryInfo dir)
    {
        foreach (FileSystemInfo entry in dir.EnumerateFileSystemInfos())
        {
            entry.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Offline);
            if (entry is DirectoryInfo sub && (sub.Attributes & FileAttributes.ReparsePoint) == 0)
            {
                SafeDelete(sub);
            }
            else if (entry is DirectoryInfo link)
            {
                link.Delete(recursive: false); // removes the link only, never the target
            }
            else
            {
                entry.Delete();
            }
        }

        dir.Delete(recursive: false);
    }
}
