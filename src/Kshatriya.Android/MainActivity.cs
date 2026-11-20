using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Database;
using Android.OS;
using Android.Provider;
using Android.Views;
using Android.Widget;
using AndroidX.AppCompat.App;
using AndroidX.Core.App;
using AndroidX.RecyclerView.Widget;
using Google.Android.Material.BottomNavigation;
using Google.Android.Material.BottomSheet;
using Google.Android.Material.Button;
using Google.Android.Material.Card;
using Google.Android.Material.Chip;
using Google.Android.Material.Color;
using Google.Android.Material.Dialog;
using Google.Android.Material.ProgressIndicator;
using Google.Android.Material.Snackbar;
using Google.Android.Material.TextField;
using Kshatriya.Core;
using Kshatriya.Mobile;
using Kshatriya.Presentation;
using Kshatriya.Updates;
using Uri = Android.Net.Uri;

namespace Kshatriya.AndroidApp;

/// <summary>
/// The app's one activity (ADR 0021): Home, Apps, History and Settings behind a navigation bar, plus first-launch
/// onboarding. It renders the state <see cref="MobileScreens"/> builds from the stores and sends user actions to
/// the scanner and content store; it holds no logic of its own beyond Android plumbing.
/// </summary>
[Activity(Label = "Kshatriya", MainLauncher = true, Icon = "@mipmap/appicon", Theme = "@style/Theme.Kshatriya", Exported = true)]
public sealed class MainActivity : AppCompatActivity
{
    private const int PickFiles = 1;
    private const int PickFolder = 2;
    private const int PickUpdate = 3;
    private const int PickKey = 4;
    private const int NotificationRequest = 10;
    private const int MaxFolderFiles = 5000;
    private const int MaxFolderDepth = 8;
    private const int MaxUpdateBytes = 256 * 1024 * 1024;
    private const string Preferences = "kshatriya-ui";

    /// <summary>The Coalition Against Stalkerware's advice for people who think they are being monitored.</summary>
    private const string SafetyAdviceUrl = "https://stopstalkerware.org/information-for-survivors/";

    private enum Page
    {
        Home,
        Apps,
        History,
        Settings,
    }

    private Protection? _protection;
    private FindingsStore? _findings;
    private Page _page = Page.Home;
    private readonly Dictionary<Page, View> _pages = [];
    private AppsFilter _appsFilter = AppsFilter.NeedsReview;
    private string _query = string.Empty;
    private IReadOnlyList<InstalledApp> _installed = [];
    private bool _busy;
    private string _busyText = string.Empty;
    private int _onboardingStep = -1;
    private RowAdapter? _appsAdapter;
    private RowAdapter? _historyAdapter;

    private FindingsStore Findings => _findings!;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        DynamicColors.ApplyToActivityIfAvailable(this);
        base.OnCreate(savedInstanceState);
        SetContentView(Resource.Layout.activity_main);
        ApplyEdgeToEdge();
        _back = new BackCallback(HandleBack);
        OnBackPressedDispatcher.AddCallback(this, _back);
        _protection = Protection.Load(this);
        _findings = Protection.Findings(this);
        Notifier.EnsureChannel(this);
        NewAppsJob.Schedule(this);

        var nav = FindViewById<BottomNavigationView>(Resource.Id.nav)!;
        nav.SetOnItemSelectedListener(new NavListener(id =>
        {
            // The bar selects the item itself after this returns: do not select it again (that would recurse).
            Show(id switch
            {
                var x when x == Resource.Id.nav_apps => Page.Apps,
                var x when x == Resource.Id.nav_history => Page.History,
                var x when x == Resource.Id.nav_settings => Page.Settings,
                _ => Page.Home,
            }, fromNavigationBar: true);
            return true;
        }));

        Show(Page.Home);
        if (!GetSharedPreferences(Preferences, FileCreationMode.Private)!.GetBoolean("onboarded", false))
        {
            ShowOnboarding(0);
        }

        // Record the starting point for new-app checks without waiting for the first job.
        Task.Run(() => NewAppsJob.CheckChangedApps(ApplicationContext!));
    }

    protected override void OnResume()
    {
        base.OnResume();
        // The user may have uninstalled an app from Android's app page, or changed notification settings.
        Task.Run(() =>
        {
            IReadOnlyList<InstalledApp> apps = Protection.InstalledAppList(this);
            Findings.AppsRemoved(new HashSet<string>(apps.Select(a => a.PackageName), StringComparer.Ordinal));
            RunOnUiThread(() =>
            {
                _installed = apps;
                Render();
            });
        });
    }

    // ===================== Navigation =====================

    private BackCallback? _back;

    /// <summary>
    /// Edge-to-edge (enforced for apps targeting Android 15 and later): the app draws behind the system bars and
    /// pads its own content. The navigation bar pads itself for the gesture area.
    /// </summary>
    private void ApplyEdgeToEdge()
    {
        AndroidX.Activity.EdgeToEdge.Enable(this);
        View main = FindViewById(Resource.Id.main)!;
        View onboarding = FindViewById(Resource.Id.onboarding)!;
        int pad = Ui.Dp(this, 24);
        AndroidX.Core.View.ViewCompat.SetOnApplyWindowInsetsListener(FindViewById(Resource.Id.root)!, new InsetsListener(bars =>
        {
            main.SetPadding(bars.Left, bars.Top, bars.Right, 0);
            onboarding.SetPadding(pad + bars.Left, pad + bars.Top, pad + bars.Right, pad + bars.Bottom);
        }));
    }

    /// <summary>
    /// Back (predictive back on Android 13 and later): steps back through onboarding, otherwise returns to Home
    /// from another page. On Home the system handles it, so the predictive animation shows leaving the app.
    /// </summary>
    private void HandleBack()
    {
        if (_onboardingStep > 0)
        {
            ShowOnboarding(_onboardingStep == 2 && !OperatingSystem.IsAndroidVersionAtLeast(33) ? 0 : _onboardingStep - 1);
        }
        else if (_onboardingStep == 0)
        {
            FinishOnboarding();
        }
        else
        {
            Show(Page.Home);
        }
    }

    private void UpdateBack()
    {
        if (_back is not null)
        {
            _back.Enabled = _onboardingStep >= 0 || _page != Page.Home;
        }
    }

    private void Show(Page page, bool fromNavigationBar = false)
    {
        _page = page;
        UpdateBack();
        var content = FindViewById<FrameLayout>(Resource.Id.content)!;
        content.RemoveAllViews();
        if (!_pages.TryGetValue(page, out View? view))
        {
            view = Create(page);
            _pages[page] = view;
        }

        content.AddView(view);
        var nav = FindViewById<BottomNavigationView>(Resource.Id.nav)!;
        int id = page switch
        {
            Page.Apps => Resource.Id.nav_apps,
            Page.History => Resource.Id.nav_history,
            Page.Settings => Resource.Id.nav_settings,
            _ => Resource.Id.nav_home,
        };
        if (!fromNavigationBar && nav.SelectedItemId != id)
        {
            nav.SelectedItemId = id;
        }

        Render();
    }

    private View Create(Page page)
    {
        LayoutInflater inflater = LayoutInflater!;
        var content = FindViewById<FrameLayout>(Resource.Id.content)!;
        switch (page)
        {
            case Page.Home:
            {
                View view = inflater.Inflate(Resource.Layout.page_home, content, false)!;
                view.FindViewById<MaterialButton>(Resource.Id.status_action)!.Click += (_, _) => Perform(CurrentStatus().PrimaryActionId ?? StatusActions.ScanApps);
                view.FindViewById<MaterialCardView>(Resource.Id.scan_files)!.Click += (_, _) => Pick(Intent.ActionOpenDocument, PickFiles, multiple: true);
                view.FindViewById<MaterialCardView>(Resource.Id.scan_folder)!.Click += (_, _) => StartActivityForResult(new Intent(Intent.ActionOpenDocumentTree), PickFolder);
                return view;
            }

            case Page.Apps:
            {
                View view = inflater.Inflate(Resource.Layout.page_list, content, false)!;
                _appsAdapter = new RowAdapter(row => OpenFinding(row.Key));
                SetUpList(view, _appsAdapter);
                var search = view.FindViewById<TextInputEditText>(Resource.Id.search)!;
                search.TextChanged += (_, e) =>
                {
                    _query = e.Text?.ToString() ?? string.Empty;
                    Render();
                };
                var chips = view.FindViewById<ChipGroup>(Resource.Id.chips)!;
                foreach (AppsFilter filter in new[] { AppsFilter.NeedsReview, AppsFilter.All, AppsFilter.NotChecked, AppsFilter.Recent })
                {
                    var chip = new Chip(this) { Checkable = true, Tag = (int)filter, Id = View.GenerateViewId() };
                    chip.Click += (_, _) =>
                    {
                        _appsFilter = filter;
                        Render();
                    };
                    chips.AddView(chip);
                }

                return view;
            }

            case Page.History:
            {
                View view = inflater.Inflate(Resource.Layout.page_list, content, false)!;
                view.FindViewById(Resource.Id.search_box)!.Visibility = ViewStates.Gone;
                view.FindViewById(Resource.Id.chips_scroll)!.Visibility = ViewStates.Gone;
                _historyAdapter = new RowAdapter(row => OpenFinding(row.Key));
                SetUpList(view, _historyAdapter);
                return view;
            }

            default:
            {
                var scroll = new ScrollView(this);
                var list = new LinearLayout(this) { Orientation = Orientation.Vertical, Id = Resource.Id.settings_list };
                list.SetPadding(0, Ui.Dp(this, 8), 0, Ui.Dp(this, 16));
                scroll.AddView(list);
                return scroll;
            }
        }
    }

    private void SetUpList(View page, RowAdapter adapter)
    {
        var list = page.FindViewById<RecyclerView>(Resource.Id.list)!;
        list.SetLayoutManager(new LinearLayoutManager(this));
        list.SetAdapter(adapter);
    }

    // ===================== Rendering =====================

    private MobileStatusInputs Inputs()
    {
        (int confirmed, int suspicious) = Findings.CountUnresolved();
        ISharedPreferences prefs = GetSharedPreferences(Preferences, FileCreationMode.Private)!;
        return new MobileStatusInputs
        {
            UnresolvedConfirmedFindings = confirmed,
            UnresolvedSuspiciousFindings = suspicious,
            ContentSequence = _protection?.ContentSequence ?? 0,
            ContentExpiresUtc = _protection?.ContentExpiresUtc,
            ContentExpired = _protection?.ContentExpired ?? false,
            LastAppScanUtc = Findings.LastAppScanUtc,
            NotificationsAllowed = NotificationManagerCompat.From(this)!.AreNotificationsEnabled(),
            Dismissed = prefs.GetStringSet("dismissed", null) is { } set ? new HashSet<string>(set) : new HashSet<string>(),
            Now = DateTimeOffset.UtcNow,
        };
    }

    private StatusSnapshot CurrentStatus() => MobileStatusEvaluator.Evaluate(Inputs());

    private void Render()
    {
        switch (_page)
        {
            case Page.Home:
                RenderHome();
                break;
            case Page.Apps:
                RenderApps();
                break;
            case Page.History:
                RenderHistory();
                break;
            default:
                RenderSettings();
                break;
        }
    }

    private void RenderHome()
    {
        View page = _pages[Page.Home];
        UpdateSettings updates = UpdateJob.ReadSettings(this);
        HomeState state = MobileScreens.Home(Inputs(), Findings, _protection?.ContentStatus ?? string.Empty,
            updates.Enabled ? "Automatic updates: daily" + (updates.UnmeteredOnly ? " on Wi-Fi" : string.Empty) : "Automatic updates: off");
        (int icon, int colour, int container, _) = Ui.Of(Ui.ToneOf(state.Status.Level));
        page.FindViewById<MaterialCardView>(Resource.Id.status_card)!.SetCardBackgroundColor(Ui.Color(this, container));
        var statusIcon = page.FindViewById<ImageView>(Resource.Id.status_icon)!;
        statusIcon.SetImageResource(icon);
        statusIcon.SetColorFilter(new Android.Graphics.Color(Ui.Color(this, colour)));
        page.FindViewById<TextView>(Resource.Id.status_headline)!.Text = state.Status.Headline;
        page.FindViewById<TextView>(Resource.Id.status_detail)!.Text = state.Status.Detail;

        var action = page.FindViewById<MaterialButton>(Resource.Id.status_action)!;
        action.Text = state.Status.PrimaryActionId switch
        {
            StatusActions.ReviewFindings => "Review",
            StatusActions.CheckUpdates => "Check for updates",
            StatusActions.AllowNotifications => "Allow notifications",
            _ => "Scan apps now",
        };
        action.Enabled = !_busy;
        page.FindViewById<LinearProgressIndicator>(Resource.Id.scan_progress)!.Visibility = _busy ? ViewStates.Visible : ViewStates.Gone;
        var busyText = page.FindViewById<TextView>(Resource.Id.scan_text)!;
        busyText.Visibility = _busy ? ViewStates.Visible : ViewStates.Gone;
        busyText.Text = _busyText;
        page.FindViewById<MaterialCardView>(Resource.Id.scan_files)!.Enabled = !_busy;
        page.FindViewById<MaterialCardView>(Resource.Id.scan_folder)!.Enabled = !_busy;

        var attention = page.FindViewById<LinearLayout>(Resource.Id.attention_list)!;
        attention.RemoveAllViews();
        foreach (StatusItem item in state.Status.Items.Take(3))
        {
            ResultTone tone = item.Level == ProtectionLevel.ActionNeeded ? ResultTone.Danger : ResultTone.Warn;
            string? actionId = item.ActionId;
            int leading = item.ActionId switch
            {
                StatusActions.ScanApps => Resource.Drawable.ic_apps,
                StatusActions.AllowNotifications => Resource.Drawable.ic_bell,
                StatusActions.CheckUpdates => Resource.Drawable.ic_download,
                _ => Resource.Drawable.ic_shield,
            };
            attention.AddView(Ui.Row(attention, new RowItem(item.Title, item.Detail, tone, Icon: leading), actionId is null ? null : () => Perform(actionId)));
        }

        // One item is already the hero's headline: list them only when there is more than one.
        bool anything = state.Status.Items.Count > 1;
        page.FindViewById(Resource.Id.attention_title)!.Visibility = anything ? ViewStates.Visible : ViewStates.Gone;
        attention.Visibility = anything ? ViewStates.Visible : ViewStates.Gone;

        var info = page.FindViewById<LinearLayout>(Resource.Id.info_list)!;
        info.RemoveAllViews();
        info.AddView(Ui.Row(info, new RowItem("Last check", state.LastChecked, ResultTone.Info, Icon: Resource.Drawable.ic_history)));
        info.AddView(Ui.Row(info, new RowItem("Signatures", state.Signatures, ResultTone.Info, Icon: Resource.Drawable.ic_download), () => Show(Page.Settings)));
        info.AddView(Ui.Row(info, new RowItem("Updates", state.Updates, ResultTone.Info, Icon: Resource.Drawable.ic_key), () => Show(Page.Settings)));
        info.AddView(Ui.Row(info, new RowItem("Works with Google Play Protect", "Keep Play Protect on. Kshatriya adds checks; it does not replace it.", ResultTone.Info, Icon: Resource.Drawable.ic_shield)));
    }

    private void RenderApps()
    {
        View page = _pages[Page.Apps];
        AppsState state = MobileScreens.Apps(_installed, Findings, _appsFilter, _query, DateTimeOffset.UtcNow);
        var chips = page.FindViewById<ChipGroup>(Resource.Id.chips)!;
        for (int i = 0; i < chips.ChildCount; i++)
        {
            var chip = (Chip)chips.GetChildAt(i)!;
            var filter = (AppsFilter)(int)chip.Tag!;
            chip.Text = filter switch
            {
                AppsFilter.NeedsReview => $"Needs review · {state.NeedsReview}",
                AppsFilter.All => $"All · {state.Total}",
                AppsFilter.NotChecked => $"Not checked · {state.NotChecked}",
                _ => $"Recent · {state.Recent}",
            };
            chip.Checked = filter == _appsFilter;
        }

        _appsAdapter!.Show(state.Rows.Select(r => new RowItem(r.Label, r.Detail, r.Tone, r.FindingKey)));
        var empty = page.FindViewById<TextView>(Resource.Id.empty)!;
        empty.Visibility = state.Rows.Count == 0 ? ViewStates.Visible : ViewStates.Gone;
        empty.Text = _installed.Count == 0 ? "Loading your apps…"
            : _appsFilter == AppsFilter.NeedsReview ? "Nothing needs your review."
            : "No apps match.";
    }

    private void RenderHistory()
    {
        View page = _pages[Page.History];
        IReadOnlyList<HistoryRow> rows = MobileScreens.History(Findings, DateTimeOffset.UtcNow);
        _historyAdapter!.Show(rows.Select(r => new RowItem(r.Title, r.Detail, r.Tone, r.FindingKey, r.When)));
        var empty = page.FindViewById<TextView>(Resource.Id.empty)!;
        empty.Visibility = rows.Count == 0 ? ViewStates.Visible : ViewStates.Gone;
        empty.Text = "Nothing yet. Scans and findings appear here.";
    }

    private void RenderSettings()
    {
        var list = _pages[Page.Settings].FindViewById<LinearLayout>(Resource.Id.settings_list)!;
        list.RemoveAllViews();
        UpdateSettings updates = UpdateJob.ReadSettings(this);
        bool notifications = NotificationManagerCompat.From(this)!.AreNotificationsEnabled();

        Section(list, "Updates");
        list.AddView(Ui.Row(list, new RowItem("Automatic updates", updates.Enabled ? "On: once a day" + (updates.UnmeteredOnly ? " on Wi-Fi" : string.Empty) : "Off. Turn on to download signed updates daily.", ResultTone.Info, Icon: Resource.Drawable.ic_download), ShowUpdateSettings));
        list.AddView(Ui.Row(list, new RowItem("Check for updates now", _protection?.ContentStatus ?? string.Empty, ResultTone.Info, Icon: Resource.Drawable.ic_download), CheckForUpdates));
        list.AddView(Ui.Row(list, new RowItem("Import a signed update…", "A .kstu file you received", ResultTone.Info, Icon: Resource.Drawable.ic_file), () => Pick(Intent.ActionOpenDocument, PickUpdate, multiple: false)));
        list.AddView(Ui.Row(list, new RowItem("Add a trusted update key…", "Only keys you created or received from someone you trust", ResultTone.Info, Icon: Resource.Drawable.ic_key), () => Pick(Intent.ActionOpenDocument, PickKey, multiple: false)));

        Section(list, "Notifications");
        list.AddView(Ui.Row(list, new RowItem("Notifications", notifications ? "Allowed: you hear about risky new apps." : "Off: you only see findings when you open Kshatriya.", notifications ? ResultTone.Info : ResultTone.Warn, Icon: Resource.Drawable.ic_bell), OpenNotificationSettings));

        Section(list, "About");
        list.AddView(Ui.Row(list, new RowItem("Kshatriya Antivirus · prototype", "Version " + (PackageManager!.GetPackageInfo(PackageName!, 0)?.VersionName ?? "?") + ". Not a replacement for Google Play Protect or any commercial antivirus.", ResultTone.Info, Icon: Resource.Mipmap.appicon)));
        list.AddView(Ui.Row(list, new RowItem("Privacy", "Checks run on this phone. Nothing about your apps or files is sent anywhere. With automatic updates on, the update server sees your IP address.", ResultTone.Info, Icon: Resource.Drawable.ic_lock)));
        list.AddView(Ui.Row(list, new RowItem("Show the introduction again", string.Empty, ResultTone.Info, Icon: Resource.Drawable.ic_history), () => ShowOnboarding(0)));
    }

    private void Section(LinearLayout list, string title)
    {
        var header = new TextView(this) { Text = title };
        header.SetTextAppearance(Resource.Style.TextAppearance_Material3_TitleSmall);
        header.SetPadding(Ui.Dp(this, 16), Ui.Dp(this, 16), Ui.Dp(this, 16), Ui.Dp(this, 4));
        if (OperatingSystem.IsAndroidVersionAtLeast(28))
        {
            header.AccessibilityHeading = true;
        }
        list.AddView(header);
    }

    // ===================== Actions =====================

    private void Perform(string actionId)
    {
        switch (actionId)
        {
            case StatusActions.ReviewFindings:
                bool apps = Findings.Findings.Any(f => f.NeedsReview && f.IsApp);
                _appsFilter = AppsFilter.NeedsReview;
                Show(apps ? Page.Apps : Page.History);
                break;
            case StatusActions.CheckUpdates:
                if (UpdateJob.ReadSettings(this).Enabled)
                {
                    CheckForUpdates();
                }
                else
                {
                    Show(Page.Settings);
                }

                break;
            case StatusActions.AllowNotifications:
                RequestNotifications();
                break;
            default:
                ScanInstalledApps();
                break;
        }
    }

    private void OpenFinding(string? key)
    {
        if (key is null || Findings.Find(key) is not { } finding)
        {
            return;
        }

        FindingSheet sheet = MobileScreens.Sheet(finding);
        var dialog = new BottomSheetDialog(this);
        View view = LayoutInflater!.Inflate(Resource.Layout.sheet_finding, null, false)!;
        view.FindViewById<TextView>(Resource.Id.sheet_title)!.Text = sheet.Title;
        ResultTone tone = !finding.NeedsReview ? ResultTone.Info : finding.Confirmed ? ResultTone.Danger : ResultTone.Warn;
        (int icon, int colour, _, _) = Ui.Of(tone);
        var verdictIcon = view.FindViewById<ImageView>(Resource.Id.sheet_icon)!;
        verdictIcon.SetImageResource(icon);
        verdictIcon.SetColorFilter(new Android.Graphics.Color(Ui.Color(this, colour)));
        view.FindViewById<TextView>(Resource.Id.sheet_verdict)!.Text = sheet.Verdict + (finding.ResolvedReason is { } why ? $" · {why}" : sheet.Kept ? " · kept by you" : string.Empty);
        view.FindViewById<TextView>(Resource.Id.sheet_explanation)!.Text = sheet.Explanation;
        if (sheet.SafetyNote is { } note)
        {
            view.FindViewById(Resource.Id.sheet_safety)!.Visibility = ViewStates.Visible;
            view.FindViewById<TextView>(Resource.Id.sheet_safety_text)!.Text = note;
            view.FindViewById<MaterialButton>(Resource.Id.sheet_safety_advice)!.Click += (_, _) =>
                StartActivity(new Intent(Intent.ActionView, Uri.Parse(SafetyAdviceUrl)));
        }

        var details = view.FindViewById<LinearLayout>(Resource.Id.sheet_details)!;
        foreach ((string label, string value) in sheet.Details)
        {
            var caption = new TextView(this) { Text = label };
            caption.SetTextAppearance(Resource.Style.TextAppearance_Material3_LabelMedium);
            caption.SetPadding(0, Ui.Dp(this, 8), 0, 0);
            var text = new TextView(this) { Text = value };
            text.SetTextAppearance(Resource.Style.TextAppearance_Material3_BodyMedium);
            text.SetTextIsSelectable(true);
            details.AddView(caption);
            details.AddView(text);
        }

        var review = view.FindViewById<MaterialButton>(Resource.Id.sheet_review)!;
        review.Visibility = sheet.CanReviewApp ? ViewStates.Visible : ViewStates.Gone;
        review.Click += (_, _) =>
        {
            dialog.Dismiss();
            StartActivity(new Intent(Settings.ActionApplicationDetailsSettings, Uri.Parse("package:" + finding.PackageName)));
        };
        var keep = view.FindViewById<MaterialButton>(Resource.Id.sheet_keep)!;
        keep.Text = sheet.Kept ? "Stop keeping" : finding.IsApp ? "Keep this app" : "Keep this file";
        keep.Visibility = finding.ResolvedReason is null ? ViewStates.Visible : ViewStates.Gone;
        keep.Click += (_, _) =>
        {
            Findings.SetKept(finding.Key, !sheet.Kept);
            dialog.Dismiss();
            Render();
            Snackbar.Make(FindViewById(Resource.Id.content)!, sheet.Kept
                ? $"{finding.DisplayName} needs your review again."
                : $"{finding.DisplayName} is kept. It no longer counts on Home; scans still report it.", Snackbar.LengthLong)!.Show();
        };
        dialog.SetContentView(view);
        dialog.Show();
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

                RunScan("files", "Scanning files…", () => [.. uris.Select(DocumentTarget)]);
                break;
            case PickFolder when data.Data is { } tree:
                RunScan("folder", "Scanning folder…", () => FolderTargets(tree));
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
        RunScan("apps", "Checking installed apps…", () => [.. Protection.InstalledAppTargets(PackageManager!).Where(t => t.PackageName != PackageName)], allApps: true);

    private void RunScan(string kind, string message, Func<List<MobileScanTarget>> targets, bool allApps = false)
    {
        if (_busy || _protection is null)
        {
            return;
        }

        SetBusy(true, message);
        Show(Page.Home);
        Protection protection = _protection;
        Task.Run(async () =>
        {
            string summary;
            bool findings = false;
            try
            {
                List<MobileScanTarget> list = targets();
                var results = new List<MobileScanResult>(list.Count);
                foreach (MobileScanTarget target in list)
                {
                    results.Add(await protection.Scanner.ScanAsync(target, CancellationToken.None));
                    if (results.Count % 5 == 0 || results.Count == list.Count)
                    {
                        int done = results.Count;
                        RunOnUiThread(() => SetBusy(true, $"{message} {done} of {list.Count}"));
                    }
                }

                Findings.Record(results, kind, "scan", DateTimeOffset.UtcNow, allApps);
                summary = MobileText.Summary(results);
                findings = results.Any(r => r.Item.Status is ScanStatus.Detected or ScanStatus.Suspicious);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                summary = $"The scan stopped: {ex.Message}";
            }
            finally
            {
                Protection.SaveCache(this);
            }

            RunOnUiThread(() =>
            {
                SetBusy(false, string.Empty);
                Snackbar bar = Snackbar.Make(FindViewById(Resource.Id.content)!, summary, Snackbar.LengthLong)!;
                if (findings)
                {
                    bar.SetAction("Review", _ => Perform(StatusActions.ReviewFindings));
                }

                bar.Show();
            });
        });
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
            Message("That file is too large to be a Kshatriya update.");
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
                SetBusy(false, string.Empty);
                Message(message);
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
            Message("That file is not a Kshatriya public key.");
            return;
        }

        new MaterialAlertDialogBuilder(this)
            .SetTitle("Trust this update key?")!
            .SetMessage($"Key {key.KeyId}. Updates signed with it can add threat signatures to Kshatriya. Only trust keys you created or received from someone you trust.")!
            .SetPositiveButton("Trust", (_, _) => Message(_protection!.Store.AddTrustedKey(key) ? $"Key {key.KeyId} is trusted." : $"Key {key.KeyId} was already trusted."))!
            .SetNegativeButton("Cancel", (_, _) => { })!
            .Show();
    }

    private void CheckForUpdates()
    {
        if (_busy)
        {
            return;
        }

        SetBusy(true, "Checking for updates…");
        Task.Run(async () =>
        {
            string message;
            try
            {
                UpdateCheckResult result = await UpdateJob.RunAsync(ApplicationContext!, CancellationToken.None);
                message = result.Outcome == UpdateCheckOutcome.Installed
                    ? result.Message + " Installed apps were checked against it."
                    : result.Message;
                _protection = Protection.Load(this);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                message = $"The update check failed: {ex.Message}";
            }

            RunOnUiThread(() =>
            {
                SetBusy(false, string.Empty);
                Message(message);
            });
        });
    }

    private void ShowUpdateSettings() => ShowUpdateSettings(null);

    private void ShowUpdateSettings(Action? done)
    {
        UpdateSettings current = UpdateJob.ReadSettings(this);
        int pad = Ui.Dp(this, 24);
        var layout = new LinearLayout(this) { Orientation = Orientation.Vertical };
        layout.SetPadding(pad, Ui.Dp(this, 8), pad, 0);
        var explanation = new TextView(this)
        {
            Text = "Once a day Kshatriya downloads the signed update from this address and installs it only if it is signed "
                + "with a key you trust and is newer than the one installed. The request contains nothing about you, this "
                + "phone or your apps, but the server sees your IP address.",
        };
        explanation.SetTextAppearance(Resource.Style.TextAppearance_Material3_BodyMedium);
        layout.AddView(explanation);
        var source = new EditText(this) { Text = current.Source, ContentDescription = "Update address" };
        source.SetSingleLine(true);
        layout.AddView(source);
        var unmetered = new CheckBox(this) { Text = "Only on Wi-Fi (unmetered networks)", Checked = current.UnmeteredOnly };
        layout.AddView(unmetered);

        new MaterialAlertDialogBuilder(this)
            .SetTitle("Automatic updates")!
            .SetView(layout)!
            .SetPositiveButton("Turn on", (_, _) =>
            {
                string address = source.Text?.Trim() ?? string.Empty;
                if (ContentUpdateChecker.ValidateSource(address) is { } problem)
                {
                    Message(problem);
                }
                else
                {
                    UpdateJob.Apply(this, new UpdateSettings(true, address, unmetered.Checked));
                }

                Render();
                done?.Invoke();
            })!
            .SetNeutralButton("Turn off", (_, _) =>
            {
                UpdateJob.Apply(this, current with { Enabled = false });
                Render();
                done?.Invoke();
            })!
            .SetNegativeButton("Cancel", (_, _) => done?.Invoke())!
            .Show();
    }

    private void SetBusy(bool busy, string text)
    {
        _busy = busy;
        _busyText = text;
        Render();
    }

    private void Message(string text) => Snackbar.Make(FindViewById(Resource.Id.content)!, text, Snackbar.LengthLong)!.Show();

    // ===================== Notifications permission =====================

    /// <summary>Asks once in context; after a denial Android's own settings are the way (no nagging).</summary>
    private void RequestNotifications()
    {
        if (OperatingSystem.IsAndroidVersionAtLeast(33)
            && CheckSelfPermission(Android.Manifest.Permission.PostNotifications) != Permission.Granted
            && !GetSharedPreferences(Preferences, FileCreationMode.Private)!.GetBoolean("asked-notifications", false))
        {
            using (ISharedPreferencesEditor editor = GetSharedPreferences(Preferences, FileCreationMode.Private)!.Edit()!)
            {
                editor.PutBoolean("asked-notifications", true);
                editor.Apply();
            }

            RequestPermissions([Android.Manifest.Permission.PostNotifications], NotificationRequest);
        }
        else
        {
            OpenNotificationSettings();
        }
    }

    private void OpenNotificationSettings()
    {
        var intent = new Intent(Settings.ActionAppNotificationSettings);
        intent.PutExtra(Settings.ExtraAppPackage, PackageName);
        StartActivity(intent);
    }

    public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
    {
        base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == NotificationRequest && _onboardingStep == 1)
        {
            ShowOnboarding(2);
        }

        Render();
    }

    // ===================== Onboarding =====================

    private void ShowOnboarding(int step)
    {
        // Android 12 and older grant notifications by default: skip that step.
        if (step == 1 && !OperatingSystem.IsAndroidVersionAtLeast(33))
        {
            step = 2;
        }

        _onboardingStep = step;
        UpdateBack();
        View overlay = FindViewById(Resource.Id.onboarding)!;
        overlay.Visibility = ViewStates.Visible;
        var badge = overlay.FindViewById(Resource.Id.onboarding_badge)!;
        var shape = new Android.Graphics.Drawables.GradientDrawable();
        shape.SetCornerRadius(Ui.Dp(this, 36));
        shape.SetColor(MaterialColors.GetColor(overlay, Resource.Attribute.colorPrimaryContainer));
        badge.Background = shape;

        (int icon, string title, string body, string note, string primary, string? secondary) = step switch
        {
            0 => (Resource.Mipmap.appicon, "Welcome to Kshatriya",
                "Kshatriya checks your installed apps and the files you choose against known threats, including stalkerware. It works alongside Google Play Protect: keep Play Protect on.",
                "Checks run on this phone. Nothing about your apps or files is sent anywhere.",
                "Continue", (string?)null),
            1 => (Resource.Drawable.ic_bell, "Hear about risky apps",
                "Kshatriya checks new and updated apps about every 15 minutes and notifies you only when it finds something. No \"all clear\" pings, no ads.",
                "Android asks next. You can change this later in Settings.",
                "Allow notifications", "Not now"),
            _ => (Resource.Drawable.ic_download, "Keep signatures up to date",
                "Kshatriya can download a signed update once a day. It is installed only if it is signed with a key you trust. This is off unless you turn it on.",
                "The request contains nothing about you, this phone or your apps. The update server sees your IP address.",
                "Set up automatic updates", "Not now"),
        };
        int total = OperatingSystem.IsAndroidVersionAtLeast(33) ? 3 : 2;
        int shown = step == 2 && total == 2 ? 2 : step + 1;
        overlay.FindViewById<TextView>(Resource.Id.onboarding_step)!.Text = $"Step {shown} of {total}";
        var iconView = overlay.FindViewById<ImageView>(Resource.Id.onboarding_icon)!;
        iconView.SetImageResource(icon);
        // The welcome step shows the Kshatriya logo in its own colours; the other steps use tinted symbols.
        iconView.ImageTintList = step == 0
            ? null
            : Android.Content.Res.ColorStateList.ValueOf(new Android.Graphics.Color(MaterialColors.GetColor(overlay, Resource.Attribute.colorOnPrimaryContainer)));
        overlay.FindViewById<TextView>(Resource.Id.onboarding_title)!.Text = title;
        overlay.FindViewById<TextView>(Resource.Id.onboarding_body)!.Text = body;
        overlay.FindViewById<TextView>(Resource.Id.onboarding_note)!.Text = note;
        var primaryButton = overlay.FindViewById<MaterialButton>(Resource.Id.onboarding_primary)!;
        primaryButton.Text = primary;
        var secondaryButton = overlay.FindViewById<MaterialButton>(Resource.Id.onboarding_secondary)!;
        secondaryButton.Text = secondary ?? string.Empty;
        secondaryButton.Visibility = secondary is null ? ViewStates.Gone : ViewStates.Visible;

        // Replace earlier handlers by recreating the click listeners for this step.
        primaryButton.SetOnClickListener(new ClickListener(() =>
        {
            switch (step)
            {
                case 0:
                    ShowOnboarding(1);
                    break;
                case 1:
                    RequestNotifications(); // the result moves on to the next step
                    if (!OperatingSystem.IsAndroidVersionAtLeast(33) || CheckSelfPermission(Android.Manifest.Permission.PostNotifications) == Permission.Granted)
                    {
                        ShowOnboarding(2);
                    }

                    break;
                default:
                    ShowUpdateSettings(FinishOnboarding);
                    break;
            }
        }));
        secondaryButton.SetOnClickListener(new ClickListener(() =>
        {
            if (step == 1)
            {
                ShowOnboarding(2);
            }
            else
            {
                FinishOnboarding();
            }
        }));
        overlay.FindViewById<MaterialButton>(Resource.Id.onboarding_skip)!.SetOnClickListener(new ClickListener(FinishOnboarding));
        overlay.FindViewById(Resource.Id.onboarding_title)!.SendAccessibilityEvent(Android.Views.Accessibility.EventTypes.ViewFocused);
    }

    private void FinishOnboarding()
    {
        _onboardingStep = -1;
        UpdateBack();
        FindViewById(Resource.Id.onboarding)!.Visibility = ViewStates.Gone;
        using (ISharedPreferencesEditor editor = GetSharedPreferences(Preferences, FileCreationMode.Private)!.Edit()!)
        {
            editor.PutBoolean("onboarded", true);
            editor.Apply();
        }

        Show(Page.Home);
    }
}

/// <summary>A click listener that replaces any earlier one (used where a view's action changes).</summary>
internal sealed class ClickListener(Action action) : Java.Lang.Object, View.IOnClickListener
{
    public void OnClick(View? v) => action();
}
