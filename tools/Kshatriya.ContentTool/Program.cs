using System.Globalization;
using System.Security.Cryptography;
using Kshatriya.Updates;

// kshatriya-content: creates signing keys and signed content packages (.kstu).
// Private keys are written to files you choose; never commit them.
if (args.Length == 0 || args[0] is "help" or "--help")
{
    Console.WriteLine("""
        kshatriya-content keygen <private-key.pem> <public-key.txt>
        kshatriya-content pack --key <private-key.pem> --sequence <n> [--channel stable] [--expires-days 30] --out <package.kstu> <file.hashdb|.yar|.model.json|.netblock|.webblock>...
        kshatriya-content verify --public-key <public-key.txt> <package.kstu>

        The public key file contains the base64 SubjectPublicKeyInfo to put in service.json "contentKeys".
        """);
    return 0;
}

try
{
    return args[0] switch
    {
        "keygen" when args.Length == 3 => KeyGen(args[1], args[2]),
        "pack" => Pack(args[1..]),
        "verify" => Verify(args[1..]),
        _ => throw new ArgumentException("Unknown command or wrong arguments. Run 'kshatriya-content help'."),
    };
}
catch (Exception ex) when (ex is ArgumentException or IOException or CryptographicException or ContentVerificationException or FormatException)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

static int KeyGen(string privatePath, string publicPath)
{
    using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using (var stream = new FileStream(privatePath, FileMode.CreateNew, FileAccess.Write))
    using (var writer = new StreamWriter(stream))
    {
        writer.Write(key.ExportPkcs8PrivateKeyPem());
    }

    byte[] spki = key.ExportSubjectPublicKeyInfo();
    File.WriteAllText(publicPath, Convert.ToBase64String(spki) + Environment.NewLine);
    Console.WriteLine($"Key id {ContentKey.IdOf(spki)}. Keep {privatePath} offline and out of source control.");
    return 0;
}

static int Pack(string[] args)
{
    string? keyPath = null, output = null, channel = "stable";
    long sequence = 0;
    int expiresDays = 30;
    var files = new List<string>();
    for (int i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--key": keyPath = args[++i]; break;
            case "--out": output = args[++i]; break;
            case "--channel": channel = args[++i]; break;
            case "--sequence": sequence = long.Parse(args[++i], CultureInfo.InvariantCulture); break;
            case "--expires-days": expiresDays = int.Parse(args[++i], CultureInfo.InvariantCulture); break;
            default: files.Add(args[i]); break;
        }
    }

    if (keyPath is null || output is null || sequence < 1 || files.Count == 0 || expiresDays is < 1 or > 365)
    {
        throw new ArgumentException("pack needs --key, --out, --sequence >= 1, --expires-days 1-365 and at least one file.");
    }

    using ECDsa key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(keyPath));
    // Web blocklists are checked here too, so a bad list fails before it is signed rather than at import.
    WebBlockList.Combine([.. files.Where(f => ContentPackage.KindOf(f) == "webblock").Select(f => WebBlockList.Parse(File.ReadAllText(f), Path.GetFileName(f)))]);
    DateTimeOffset now = DateTimeOffset.UtcNow;
    byte[] package = ContentPackage.Create(channel, sequence, now, now.AddDays(expiresDays), [.. files.Select(f => (Path.GetFileName(f), File.ReadAllBytes(f)))], key);
    File.WriteAllBytes(output, package);
    Console.WriteLine($"Wrote {output}: sequence {sequence}, {files.Count} file(s), expires {now.AddDays(expiresDays):u}.");
    return 0;
}

static int Verify(string[] args)
{
    if (args.Length != 3 || args[0] != "--public-key")
    {
        throw new ArgumentException("verify needs --public-key <file> <package>.");
    }

    VerifiedContent content = ContentPackage.Verify(File.ReadAllBytes(args[2]), [ContentKey.Parse(File.ReadAllText(args[1]).Trim())], DateTimeOffset.UtcNow);
    Console.WriteLine($"Valid: sequence {content.Manifest.Sequence}, channel {content.Manifest.Channel}, {content.Files.Count} file(s), expires {content.Manifest.ExpiresUtc:u}.");
    return 0;
}
