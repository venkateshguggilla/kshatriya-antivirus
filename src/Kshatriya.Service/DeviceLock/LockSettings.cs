using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kshatriya.Service.DeviceLock;

/// <summary>
/// The removable-drive lock settings and the Kshatriya password hash (ADR 0023), stored in <c>lock.json</c>
/// (SYSTEM and Administrators only). The password itself is never stored, logged or audited.
/// </summary>
public sealed class LockSettings
{
    public const int MinLength = 8;
    public const int MaxLength = 256;
    public const int Iterations = 600_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    /// <summary>Consecutive wrong passwords allowed before attempts are slowed down.</summary>
    public const int FreeAttempts = 5;

    private static readonly TimeSpan s_firstDelay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan s_maxDelay = TimeSpan.FromMinutes(15);

    private readonly string _file;
    private readonly bool _production;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private Stored _stored;
    private int _failures;
    private DateTimeOffset _notBefore = DateTimeOffset.MinValue;

    public LockSettings(string stateDirectory, bool production, TimeProvider time)
    {
        _file = Path.Combine(stateDirectory, "lock.json");
        _production = production;
        _time = time;
        _stored = Load(_file);
    }

    public bool Enabled
    {
        get
        {
            lock (_gate)
            {
                return _stored.Enabled && _stored.Hash is not null;
            }
        }
    }

    public bool PasswordSet
    {
        get
        {
            lock (_gate)
            {
                return _stored.Hash is not null;
            }
        }
    }

    /// <summary>Seconds until the next password attempt is accepted (0 when attempts are allowed).</summary>
    public int RetryAfterSeconds
    {
        get
        {
            lock (_gate)
            {
                TimeSpan wait = _notBefore - _time.GetUtcNow();
                return wait > TimeSpan.Zero ? (int)Math.Ceiling(wait.TotalSeconds) : 0;
            }
        }
    }

    /// <summary>Why a new password is not acceptable, or null.</summary>
    public static string? Validate(string password) =>
        password.Length < MinLength ? $"The password must have at least {MinLength} characters."
        : password.Length > MaxLength ? $"The password can have at most {MaxLength} characters."
        : string.IsNullOrWhiteSpace(password) ? "The password cannot be only spaces."
        : null;

    /// <summary>Outcome of a password check.</summary>
    public enum Check
    {
        Correct,
        Wrong,
        NotSet,
        TooManyAttempts,
    }

    /// <summary>Checks a password, counting wrong attempts service-wide and slowing them down after five.</summary>
    public Check Verify(string password)
    {
        Stored stored;
        lock (_gate)
        {
            if (_stored.Hash is null)
            {
                return Check.NotSet;
            }

            if (_time.GetUtcNow() < _notBefore)
            {
                return Check.TooManyAttempts;
            }

            stored = _stored;
        }

        bool correct = Matches(password, stored);
        lock (_gate)
        {
            if (correct)
            {
                _failures = 0;
                _notBefore = DateTimeOffset.MinValue;
                return Check.Correct;
            }

            _failures++;
            if (_failures >= FreeAttempts)
            {
                double factor = Math.Pow(2, Math.Min(_failures - FreeAttempts, 10));
                TimeSpan delay = TimeSpan.FromSeconds(Math.Min(s_firstDelay.TotalSeconds * factor, s_maxDelay.TotalSeconds));
                _notBefore = _time.GetUtcNow() + delay;
            }

            return Check.Wrong;
        }
    }

    /// <summary>Stores a new password hash (the caller has authorised the change).</summary>
    public void SetPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] hash = Derive(password, salt, Iterations);
        lock (_gate)
        {
            _stored = _stored with { Hash = Convert.ToBase64String(hash), Salt = Convert.ToBase64String(salt), Iterations = Iterations };
            _failures = 0;
            _notBefore = DateTimeOffset.MinValue;
            Save();
        }
    }

    public void SetEnabled(bool enabled)
    {
        lock (_gate)
        {
            _stored = _stored with { Enabled = enabled };
            Save();
        }
    }

    private static bool Matches(string password, Stored stored)
    {
        if (stored.Hash is null || stored.Salt is null)
        {
            return false;
        }

        byte[] expected;
        byte[] salt;
        try
        {
            expected = Convert.FromBase64String(stored.Hash);
            salt = Convert.FromBase64String(stored.Salt);
        }
        catch (FormatException)
        {
            return false;
        }

        byte[] actual = Derive(password, salt, stored.Iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt, int iterations)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(bytes, salt, Math.Clamp(iterations, 100_000, 10_000_000), HashAlgorithmName.SHA256, HashBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private void Save() =>
        SecureStorage.WriteProtectedFile(_file, JsonSerializer.Serialize(_stored, LockJsonContext.Default.Stored), _production);

    private static Stored Load(string file)
    {
        try
        {
            return File.Exists(file) && new FileInfo(file).Length < 4096
                ? JsonSerializer.Deserialize(File.ReadAllBytes(file), LockJsonContext.Default.Stored) ?? new Stored()
                : new Stored();
        }
        catch (JsonException)
        {
            // A damaged file means no password: the lock stays off until an administrator sets one.
            return new Stored();
        }
    }

    internal sealed record Stored
    {
        public int Version { get; init; } = 1;

        public bool Enabled { get; init; }

        /// <summary>PBKDF2-HMAC-SHA256 output, base64.</summary>
        public string? Hash { get; init; }

        public string? Salt { get; init; }

        public int Iterations { get; init; } = LockSettings.Iterations;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, MaxDepth = 4)]
[JsonSerializable(typeof(LockSettings.Stored))]
internal sealed partial class LockJsonContext : JsonSerializerContext
{
}
