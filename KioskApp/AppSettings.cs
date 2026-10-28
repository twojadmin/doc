using System.IO;
using System.Text.Json;

namespace KioskApp;

public sealed class AppSettings
{
    public string StartUrl { get; set; } = "";
    public string LogoutUrl { get; set; } = "";
    public string TrustedOrigin { get; set; } = "";
    public double MiniWidth { get; set; } = 300;
    public double MiniHeight { get; set; } = 64;
    public double MiniMargin { get; set; } = 12;

    public static AppSettings Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(path))
            return new AppSettings();

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };
        return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), options) ?? new AppSettings();
    }
}
