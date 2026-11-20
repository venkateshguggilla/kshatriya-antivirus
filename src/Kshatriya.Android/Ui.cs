using Android.Content;
using Android.Graphics.Drawables;
using Android.Views;
using Android.Widget;
using AndroidX.RecyclerView.Widget;
using Google.Android.Material.Navigation;
using Kshatriya.Mobile;
using Kshatriya.Presentation;

namespace Kshatriya.AndroidApp;

/// <summary>One list row: a letter avatar, title, supporting text, an optional trailing label and a status.</summary>
internal sealed record RowItem(string Title, string Detail, ResultTone Tone, string? Key = null, string? Trailing = null, int? Icon = null);

/// <summary>A RecyclerView adapter for <see cref="RowItem"/> rows (item_row.xml).</summary>
internal sealed class RowAdapter(Action<RowItem> click) : RecyclerView.Adapter
{
    private List<RowItem> _items = [];

    public override int ItemCount => _items.Count;

    public void Show(IEnumerable<RowItem> items)
    {
        _items = [.. items];
        NotifyDataSetChanged();
    }

    public override RecyclerView.ViewHolder OnCreateViewHolder(ViewGroup parent, int viewType)
    {
        View view = LayoutInflater.From(parent.Context)!.Inflate(Resource.Layout.item_row, parent, false)!;
        var holder = new RowHolder(view);
        view.Click += (_, _) =>
        {
            int position = holder.BindingAdapterPosition;
            if (position >= 0 && position < _items.Count)
            {
                click(_items[position]);
            }
        };
        return holder;
    }

    public override void OnBindViewHolder(RecyclerView.ViewHolder holder, int position) =>
        ((RowHolder)holder).Bind(_items[position]);

    private sealed class RowHolder(View view) : RecyclerView.ViewHolder(view)
    {
        public void Bind(RowItem item) => Ui.BindRow(ItemView, item);
    }
}

/// <summary>Colours, icons and small view helpers shared by the pages.</summary>
internal static class Ui
{
    public static int Dp(Context context, int value) => (int)(value * context.Resources!.DisplayMetrics!.Density);

    public static int Color(Context context, int id) => context.GetColor(id);

    /// <summary>The status icon for a tone: each has its own shape, so colour never carries meaning alone.</summary>
    public static (int Icon, int Colour, int Container, string Words) Of(ResultTone tone) => tone switch
    {
        ResultTone.Danger => (Resource.Drawable.ic_alert, Resource.Color.danger, Resource.Color.danger_container, "threat"),
        ResultTone.Warn => (Resource.Drawable.ic_warn, Resource.Color.warn, Resource.Color.warn_container, "to review"),
        ResultTone.Ok => (Resource.Drawable.ic_check, Resource.Color.ok, Resource.Color.ok_container, "no match"),
        _ => (Resource.Drawable.ic_dash, Resource.Color.info, Resource.Color.info_container, string.Empty),
    };

    public static ResultTone ToneOf(ProtectionLevel level) => level switch
    {
        ProtectionLevel.Protected => ResultTone.Ok,
        ProtectionLevel.AttentionRecommended => ResultTone.Warn,
        ProtectionLevel.ActionNeeded or ProtectionLevel.NotRunning => ResultTone.Danger,
        _ => ResultTone.Info,
    };

    /// <summary>Fills an item_row view.</summary>
    public static void BindRow(View view, RowItem item)
    {
        Context context = view.Context!;
        (int icon, int colour, int container, string words) = Of(item.Tone);
        var avatar = view.FindViewById<TextView>(Resource.Id.avatar)!;
        var background = new GradientDrawable();
        background.SetCornerRadius(Dp(context, 12));
        background.SetColor(Color(context, container));
        avatar.Background = background;
        if (item.Icon is { } leading)
        {
            avatar.Text = string.Empty;
            Drawable? drawable = context.GetDrawable(leading);
            if (context.Resources!.GetResourceTypeName(leading) == "mipmap")
            {
                // The logo keeps its own colours, at icon size.
                drawable?.SetBounds(0, 0, Dp(context, 24), Dp(context, 24));
                avatar.SetCompoundDrawablesRelative(drawable, null, null, null);
            }
            else
            {
                drawable?.SetTint(Color(context, colour));
                avatar.SetCompoundDrawablesRelativeWithIntrinsicBounds(drawable, null, null, null);
            }

            avatar.SetPadding(Dp(context, 8), 0, 0, 0);
        }
        else
        {
            avatar.SetCompoundDrawablesRelativeWithIntrinsicBounds(null, null, null, null);
            avatar.SetPadding(0, 0, 0, 0);
            avatar.Text = item.Title.Length > 0 ? char.ToUpperInvariant(item.Title[0]).ToString() : "?";
            avatar.SetTextColor(new Android.Graphics.Color(Color(context, colour)));
        }

        view.FindViewById<TextView>(Resource.Id.title)!.Text = item.Title;
        var detail = view.FindViewById<TextView>(Resource.Id.detail)!;
        detail.Text = item.Detail;
        detail.Visibility = item.Detail.Length > 0 ? ViewStates.Visible : ViewStates.Gone;
        var trailing = view.FindViewById<TextView>(Resource.Id.trailing)!;
        trailing.Text = item.Trailing ?? string.Empty;
        trailing.Visibility = item.Trailing is null ? ViewStates.Gone : ViewStates.Visible;
        var status = view.FindViewById<ImageView>(Resource.Id.status)!;
        status.SetImageResource(icon);
        status.SetColorFilter(new Android.Graphics.Color(Color(context, colour)));
        status.Visibility = item.Tone == ResultTone.Info && item.Icon is not null ? ViewStates.Gone : ViewStates.Visible;
        view.ContentDescription = string.Join(". ", new[] { item.Title, item.Detail, words, item.Trailing }.Where(s => !string.IsNullOrEmpty(s)));
    }

    /// <summary>Inflates and fills an item_row for a plain (non-recycled) list.</summary>
    public static View Row(ViewGroup parent, RowItem item, Action? click = null)
    {
        View view = LayoutInflater.From(parent.Context)!.Inflate(Resource.Layout.item_row, parent, false)!;
        BindRow(view, item);
        if (click is not null)
        {
            view.Click += (_, _) => click();
        }
        else
        {
            view.Clickable = false;
            view.Background = null;
        }

        return view;
    }
}

/// <summary>Navigation bar selection, as a Java listener.</summary>
internal sealed class NavListener(Func<int, bool> selected) : Java.Lang.Object, NavigationBarView.IOnItemSelectedListener
{
    public bool OnNavigationItemSelected(IMenuItem item) => selected(item.ItemId);
}

/// <summary>Back handling registered with the activity's back dispatcher (supports predictive back).</summary>
internal sealed class BackCallback(Action back) : AndroidX.Activity.OnBackPressedCallback(false)
{
    public override void HandleOnBackPressed() => back();
}

/// <summary>Hands the system bar and display cutout insets to the activity; the insets are passed on unchanged.</summary>
internal sealed class InsetsListener(Action<AndroidX.Core.Graphics.Insets> apply) : Java.Lang.Object, AndroidX.Core.View.IOnApplyWindowInsetsListener
{
    public AndroidX.Core.View.WindowInsetsCompat? OnApplyWindowInsets(View? v, AndroidX.Core.View.WindowInsetsCompat? insets)
    {
        if (insets is not null)
        {
            apply(insets.GetInsets(AndroidX.Core.View.WindowInsetsCompat.Type.SystemBars() | AndroidX.Core.View.WindowInsetsCompat.Type.DisplayCutout())!);
        }

        return insets;
    }
}
