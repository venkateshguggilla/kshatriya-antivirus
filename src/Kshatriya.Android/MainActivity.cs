using Android.App;
using Android.Content;
using Android.Database;
using Android.OS;
using Android.Provider;
using Android.Views;
using Android.Widget;
using Kshatriya.Core;
using Kshatriya.Mobile;
using Kshatriya.Updates;
using Uri = Android.Net.Uri;

namespace Kshatriya.AndroidApp;

/// <summary>The one screen: scan apps or files, import signed updates, and review results (ADR 0020).</summary>
[Activity(Label = "Kshatriya", MainLauncher = true, Icon = "@mipmap/appicon", Theme = "@android:style/Theme.Material.Light.DarkActionBar", Exported = true)]
public sealed class MainActivity : Activity
{
    private const int PickFiles = 1;
    private const int PickFolder = 2;
    private const int PickUpdate = 3;
    private const int PickKey = 4;
    private const int MaxFolderFiles = 5000;
    private const int MaxFolderDepth = 8;
    private const int MaxUpdateBytes = 256 * 1024 * 1024;

    private readonly List<MobileScanResult> _results = [];
    private ArrayAdapter<string>? _adapter;
    private TextView? _status;
    private TextView? _summary;
    private Button[] _buttons = [];
    private Protection? _protection;
    private bool _busy;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        SetContentView(BuildLayout());
        _protection = Protection.Load(this);
        ShowStatus();
        Notifier.EnsureChannel(this);
        NewAppsJob.Schedule(this);
        if (OperatingSystem.IsAndroidVersionAtLeast(33) && CheckSelfPermission(Android.Manifest.Permission.PostNotifications) != Android.Content.PM.Permission.Granted)
        {
            RequestPermissions([Android.Manifest.Permission.PostNotifications], 0);
        }

        // Record the starting point for new-app checks without waiting for the first job.
        Task.Run(() => NewAppsJob.CheckChangedApps(ApplicationContext!));
    }

    private LinearLayout BuildLayout()
    {
        int pad = Dp(16);
        var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
        root.SetPadding(pad, pad, pad, pad);

        var title = new TextView(this) { Text = "Kshatriya Antivirus (prototype)", TextSize = 22 };
        var note = new TextView(this)
        {
            Text = "Works alongside Google Play Protect; keep it on. Checks run on this phone and nothing is sent anywhere. "
                + "Apps and files are compared with known threats by their exact fingerprint (SHA-256).",
            TextSize = 13,
        };
        _status = new TextView(this) { TextSize = 13 };
        _status.SetPadding(0, Dp(8), 0, Dp(8));
        root.AddView(title);
        root.AddView(note);
        root.AddView(_status);

        _buttons =
        [
            AddButton(root, "Scan installed apps", (_, _) => ScanInstalledApps()),
            AddButton(root, "Scan files…", (_, _) => Pick(Intent.ActionOpenDocument, PickFiles, multiple: true)),
            AddButton(root, "Scan a folder…", (_, _) => StartActivityForResult(new Intent(Intent.ActionOpenDocumentTree), PickFolder)),
            AddButton(root, "Import signed update…", (_, _) => Pick(Intent.ActionOpenDocument, PickUpdate, multiple: false)),
            AddButton(root, "Add trusted update key…", (_, _) => Pick(Intent.ActionOpenDocument, PickKey, multiple: false)),
        ];

        _summary = new TextView(this) { Text = "Choose what to scan.", TextSize = 15 };
        _summary.SetPadding(0, Dp(12), 0, Dp(4));
        root.AddView(_summary);

        _adapter = new ArrayAdapter<string>(this, Android.Resource.Layout.SimpleListItem1, new List<string>());
        var list = new ListView(this) { Adapter = _adapter };
        list.ItemClick += (_, e) => Review(e.Position);
        root.AddView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1f));
        return root;
    }

    private Button AddButton(LinearLayout root, string text, EventHandler handler)
    {
        var button = new Button(this) { Text = text };
        button.Click += handler;
        root.AddView(button, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent));
        return button;
    }

    private void Pick(string action, int request, bool multiple)
    {
        var intent = new Intent(action);
        intent.AddCategory(Intent.CategoryOpenable);
        intent.SetType("*/*");
        intent.PutExtra(Intent.ExtraAllowMultiple, multiple);
        StartActivityForResult(intent, request);
    }

    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);
        if (resultCode != Result.Ok || data is null)
        {
            return;
        }

        switch (requestCode)
        {
            case PickFiles:
                List<Uri> uris = [];
                if (data.ClipData is { } clip)
                {
                    for (int i = 0; i < clip.ItemCount; i++)
                    {
                        if (clip.GetItemAt(i)?.Uri is { } uri)
                        {
                            uris.Add(uri);
                        }
                    }
                }
                else if (data.Data is { } single)
                {
                    uris.Add(single);
                }

                RunScan("Scanning files…", () => uris.Select(DocumentTarget).ToList());
                break;
            case PickFolder when data.Data is { } tree:
                RunScan("Scanning folder…", () => FolderTargets(tree));
                break;
            case PickUpdate when data.Data is { } update:
                ImportUpdate(update);
                break;
            case PickKey when data.Data is { } key:
                AddKey(key);
                break;
        }
    }

    private void ScanInstalledApps() =>
        RunScan("Scanning installed apps…", () => Protection.InstalledAppTargets(PackageManager!).ToList());

    private void RunScan(string message, Func<List<MobileScanTarget>> targets)
    {
        if (_busy || _protection is null)
        {
            return;
        }

        SetBusy(true, message);
        _results.Clear();
        _adapter!.Clear();
        Protection protection = _protection;
        Task.Run(async () =>
        {
            try
            {
                var clock = System.Diagnostics.Stopwatch.StartNew();
                List<MobileScanTarget> list = targets();
                int done = 0;
                int cachedBefore = protection.Scanner.CacheHits;
                foreach (MobileScanTarget target in list)
                {
                    MobileScanResult result = await protection.Scanner.ScanAsync(target, CancellationToken.None);
                    done++;
                    RunOnUiThread(() =>
                    {
                        _results.Add(result);
                        _adapter!.Add(Line(result));
                        _summary!.Text = $"{message} {done} of {list.Count}";
                    });
                }

                int reused = protection.Scanner.CacheHits - cachedBefore;
                string timing = $" Took {clock.Elapsed.TotalSeconds:0} s" + (reused > 0 ? $"; {reused} unchanged file(s) were not read again." : ".");
                RunOnUiThread(() =>
                {
                    SortResults();
                    _summary!.Text = MobileText.Summary(_results) + timing + (_results.Any(r => r.Target.PackageName is not null && r.Item.Status is ScanStatus.Detected or ScanStatus.Suspicious) ? " Tap a finding to review the app." : string.Empty);
                });
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                RunOnUiThread(() => _summary!.Text = $"The scan stopped: {ex.Message}");
            }
            finally
            {
                Protection.SaveCache(this);
                RunOnUiThread(() => SetBusy(false, null));
            }
        });
    }

    /// <summary>Findings first, then items not scanned, then clean ones.</summary>
    private void SortResults()
    {
        List<MobileScanResult> sorted = [.. _results.OrderBy(r => r.Item.Status switch
        {
            ScanStatus.Detected => 0,
            ScanStatus.Suspicious => 1,
            ScanStatus.NotScanned or ScanStatus.Skipped => 2,
            _ => 3,
        })];
        _results.Clear();
        _results.AddRange(sorted);
        _adapter!.Clear();
        _adapter.AddAll(sorted.Select(Line).ToList());
    }

    private static string Line(MobileScanResult result)
    {
        (ResultTone tone, string text) = MobileText.Describe(result);
        string mark = tone switch
        {
            ResultTone.Danger => "⛔",
            ResultTone.Warn => "⚠",
            ResultTone.Info => "ℹ",
            _ => "✓",
        };
        return $"{mark}  {text}";
    }

    /// <summary>Opens Android's app details for an app finding, where the user can uninstall it.</summary>
    private void Review(int position)
    {
        if (position < 0 || position >= _results.Count || _results[position].Target.PackageName is not { } package)
        {
            return;
        }

        var intent = new Intent(Settings.ActionApplicationDetailsSettings, Uri.Parse("package:" + package));
        StartActivity(intent);
    }

    private MobileScanTarget DocumentTarget(Uri uri)
    {
        (string name, long? size) = Describe(uri);
        return new MobileScanTarget(name, uri.ToString()!, size, () => ContentResolver!.OpenInputStream(uri) ?? throw new FileNotFoundException());
    }

    private (string Name, long? Size) Describe(Uri uri)
    {
        string name = uri.LastPathSegment ?? "file";
        long? size = null;
        using ICursor? cursor = ContentResolver!.Query(uri, [IOpenableColumns.DisplayName, IOpenableColumns.Size], null, null, null);
        if (cursor is not null && cursor.MoveToFirst())
        {
            name = cursor.GetString(0) ?? name;
            if (!cursor.IsNull(1))
            {
                size = cursor.GetLong(1);
            }
        }

        return (name, size);
    }

    /// <summary>The files in a picked folder and its subfolders, within depth and count limits.</summary>
    private List<MobileScanTarget> FolderTargets(Uri tree)
    {
        var targets = new List<MobileScanTarget>();
        var pending = new Stack<(string DocumentId, int Depth)>();
        pending.Push((DocumentsContract.GetTreeDocumentId(tree)!, 0));
        while (pending.Count > 0 && targets.Count < MaxFolderFiles)
        {
            (string parent, int depth) = pending.Pop();
            Uri children = DocumentsContract.BuildChildDocumentsUriUsingTree(tree, parent)!;
            using ICursor? cursor = ContentResolver!.Query(children, [DocumentsContract.Document.ColumnDocumentId, DocumentsContract.Document.ColumnDisplayName, DocumentsContract.Document.ColumnMimeType, DocumentsContract.Document.ColumnSize], null, null, null);
            while (cursor is not null && cursor.MoveToNext() && targets.Count < MaxFolderFiles)
            {
                string id = cursor.GetString(0)!;
                string name = cursor.GetString(1) ?? id;
                if (cursor.GetString(2) == DocumentsContract.Document.MimeTypeDir)
                {
                    if (depth < MaxFolderDepth)
                    {
                        pending.Push((id, depth + 1));
                    }

                    continue;
                }

                Uri document = DocumentsContract.BuildDocumentUriUsingTree(tree, id)!;
                long? size = cursor.IsNull(3) ? null : cursor.GetLong(3);
                targets.Add(new MobileScanTarget(name, document.ToString()!, size, () => ContentResolver!.OpenInputStream(document) ?? throw new FileNotFoundException()));
            }
        }

        return targets;
    }

    private void ImportUpdate(Uri uri)
    {
        (_, long? size) = Describe(uri);
        if (size > MaxUpdateBytes)
        {
            Toast.MakeText(this, "That file is too large to be a Kshatriya update.", ToastLength.Long)!.Show();
            return;
        }

        SetBusy(true, "Checking the update…");
        Task.Run(() =>
        {
            string message;
            try
            {
                using Stream input = ContentResolver!.OpenInputStream(uri) ?? throw new FileNotFoundException();
                using var buffer = new MemoryStream();
                input.CopyTo(buffer);
                ContentImportResult result = _protection!.Store.Import(buffer.ToArray(), DateTimeOffset.UtcNow);
                message = result.Message;
                if (result.Succeeded)
                {
                    _protection = Protection.Load(this);
                }
            }
            catch (IOException ex)
            {
                message = $"The update could not be read: {ex.Message}";
            }

            RunOnUiThread(() =>
            {
                SetBusy(false, message);
                ShowStatus();
            });
        });
    }

    private void AddKey(Uri uri)
    {
        ContentKey key;
        try
        {
            using Stream input = ContentResolver!.OpenInputStream(uri) ?? throw new FileNotFoundException();
            using var reader = new StreamReader(input);
            char[] text = new char[4096];
            int read = reader.ReadBlock(text, 0, text.Length);
            key = MobileContentStore.ReadKey(new string(text, 0, read));
        }
        catch (Exception ex) when (ex is IOException or FormatException or System.Security.Cryptography.CryptographicException)
        {
            Toast.MakeText(this, "That file is not a Kshatriya public key.", ToastLength.Long)!.Show();
            return;
        }

        new AlertDialog.Builder(this)
            .SetTitle("Trust this update key?")!
            .SetMessage($"Key {key.KeyId}. Updates signed with it can add threat signatures to Kshatriya. Only trust keys you created or received from someone you trust.")!
            .SetPositiveButton("Trust", (_, _) =>
            {
                string text = _protection!.Store.AddTrustedKey(key) ? $"Key {key.KeyId} is trusted." : $"Key {key.KeyId} was already trusted.";
                Toast.MakeText(this, text, ToastLength.Long)!.Show();
            })!
            .SetNegativeButton("Cancel", (_, _) => { })!
            .Show();
    }

    private void ShowStatus() => _status!.Text = _protection?.ContentStatus;

    private void SetBusy(bool busy, string? message)
    {
        _busy = busy;
        foreach (Button button in _buttons)
        {
            button.Enabled = !busy;
        }

        if (message is not null)
        {
            _summary!.Text = message;
        }
    }

    private int Dp(int value) => (int)(value * Resources!.DisplayMetrics!.Density);
}
