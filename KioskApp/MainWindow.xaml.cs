using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using Microsoft.Web.WebView2.Core;

namespace KioskApp;

public partial class MainWindow : Window
{
    private const string DemoHost = "kiosk.local";

    private readonly AppSettings _settings = AppSettings.Load();
    private bool _isKiosk = true;
    private bool _allowClose;
    private string _startUrl = "";
    private string _trustedOrigin = "";

    public MainWindow()
    {
        InitializeComponent();
        // Pełny ekran od pierwszej klatki, zanim załaduje się WebView2.
        Left = 0;
        Top = 0;
        Width = SystemParameters.PrimaryScreenWidth;
        Height = SystemParameters.PrimaryScreenHeight;
        Loaded += OnLoaded;
        Closing += OnClosing;
        Deactivated += OnDeactivated;
        PreviewKeyDown += OnPreviewKeyDown;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        EnterKioskMode();

        // Dane WebView2 (cookies, sesja) w profilu użytkownika, nie obok .exe.
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KioskApp");
        var env = await CoreWebView2Environment.CreateAsync(null, dataDir);
        await Web.EnsureCoreWebView2Async(env);

        var core = Web.CoreWebView2;
        core.Settings.AreDevToolsEnabled = false;
        core.Settings.AreDefaultContextMenusEnabled = false;
        core.Settings.AreBrowserAcceleratorKeysEnabled = false; // brak Ctrl+P, F5, Ctrl+F itd.
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.IsZoomControlEnabled = false;

        // Linki otwierane w nowym oknie ładujemy w tym samym widoku.
        core.NewWindowRequested += (_, args) =>
        {
            args.Handled = true;
            core.Navigate(args.Uri);
        };

        core.WebMessageReceived += OnWebMessageReceived;

        if (string.IsNullOrWhiteSpace(_settings.StartUrl))
        {
            // Tryb demo: strona z folderu wwwroot pod https://kiosk.local/
            core.SetVirtualHostNameToFolderMapping(
                DemoHost,
                Path.Combine(AppContext.BaseDirectory, "wwwroot"),
                CoreWebView2HostResourceAccessKind.Deny);
            _startUrl = $"https://{DemoHost}/login.html";
        }
        else
        {
            _startUrl = _settings.StartUrl;
        }

        _trustedOrigin = !string.IsNullOrWhiteSpace(_settings.TrustedOrigin)
            ? _settings.TrustedOrigin.TrimEnd('/')
            : new Uri(_startUrl).GetLeftPart(UriPartial.Authority);

        core.Navigate(_startUrl);
    }

    // Strona wysyła:
    //   window.chrome.webview.postMessage({ type: "login", user: "Jan Kowalski" })
    //   window.chrome.webview.postMessage({ type: "logout" })
    private void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        // Przyjmujemy komunikaty tylko z zaufanej strony.
        if (!e.Source.StartsWith(_trustedOrigin + "/", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("type", out var type))
                return;

            switch (type.GetString())
            {
                case "login":
                    var user = root.TryGetProperty("user", out var u) ? u.GetString() : null;
                    EnterMiniMode(string.IsNullOrWhiteSpace(user) ? "Użytkownik" : user!);
                    break;
                case "logout":
                    Logout();
                    break;
            }
        }
        catch (JsonException)
        {
            // Ignorujemy niepoprawne komunikaty.
        }
    }

    private void EnterKioskMode()
    {
        _isKiosk = true;

        MiniPanel.Visibility = Visibility.Collapsed;
        Web.Visibility = Visibility.Visible;

        // Cały ekran główny, łącznie z paskiem zadań.
        WindowState = WindowState.Normal;
        Left = 0;
        Top = 0;
        Width = SystemParameters.PrimaryScreenWidth;
        Height = SystemParameters.PrimaryScreenHeight;
        Topmost = true;

        Activate();
        Web.Focus();
    }

    private void EnterMiniMode(string userName)
    {
        _isKiosk = false;

        UserNameText.Text = userName;
        // WebView zostaje w pamięci (sesja trwa), tylko go chowamy.
        Web.Visibility = Visibility.Collapsed;
        MiniPanel.Visibility = Visibility.Visible;

        // Prawy dolny róg obszaru roboczego (nad paskiem zadań).
        var area = SystemParameters.WorkArea;
        Width = _settings.MiniWidth;
        Height = _settings.MiniHeight;
        Left = area.Right - Width - _settings.MiniMargin;
        Top = area.Bottom - Height - _settings.MiniMargin;
        Topmost = true;
    }

    private void Logout()
    {
        var url = string.IsNullOrWhiteSpace(_settings.LogoutUrl) ? _startUrl : _settings.LogoutUrl;
        Web.CoreWebView2?.Navigate(url);
        EnterKioskMode();
    }

    private void Logout_Click(object sender, RoutedEventArgs e) => Logout();

    // Małe okno można przesunąć myszą.
    private void MiniPanel_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed)
            DragMove();
    }

    // W trybie kiosk okno wraca na wierzch, gdy straci fokus.
    private void OnDeactivated(object? sender, EventArgs e)
    {
        if (_isKiosk)
            Dispatcher.InvokeAsync(() => Activate());
    }

    // Blokada Alt+F4. Wyjście serwisowe: Ctrl+Alt+Shift+Q.
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_allowClose)
            e.Cancel = true;
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        var mods = Keyboard.Modifiers;
        if (e.Key == Key.Q &&
            mods.HasFlag(ModifierKeys.Control) &&
            mods.HasFlag(ModifierKeys.Alt) &&
            mods.HasFlag(ModifierKeys.Shift))
        {
            _allowClose = true;
            Close();
        }
    }
}
