using Jrss.Core;

namespace Jrss.Ui;

internal static class ConsoleUi
{
    public static void Clear()
    {
        try
        {
            if (!Console.IsOutputRedirected)
            {
                Console.Clear();
            }
        }
        catch (IOException) { }
        catch (PlatformNotSupportedException) { }
    }

    public static void BeginScreen(string title, string? description = null)
    {
        Clear();
        Banner();
        Section(title);
        if (!string.IsNullOrWhiteSpace(description))
        {
            Info(description);
            Console.WriteLine();
        }
    }

    public static void Banner()
    {
        WriteLine(" ▄▄▄██▀▀▀██▀███    ██████   ██████ ", ConsoleColor.Red);
        WriteLine("   ▒██  ▓██ ▒ ██▒▒██    ▒ ▒██    ▒ ", ConsoleColor.Red);
        WriteLine("   ░██  ▓██ ░▄█ ▒░ ▓██▄   ░ ▓██▄   ", ConsoleColor.Red);
        WriteLine("▓██▄██▓ ▒██▀▀█▄    ▒   ██▒  ▒   ██▒", ConsoleColor.Red);
        WriteLine(" ▓███▒  ░██▓ ▒██▒▒██████▒▒▒██████▒▒", ConsoleColor.Red);
        WriteLine(" ▒▓▒▒░  ░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░", ConsoleColor.Red);
        WriteLine(" ▒ ░▒░    ░▒ ░ ▒░░ ░▒  ░ ░░ ░▒  ░ ░", ConsoleColor.Red);
        WriteLine(" ░ ░ ░    ░░   ░ ░  ░  ░  ░  ░  ░  ", ConsoleColor.Red);
        WriteLine(" ░   ░     ░           ░        ░   ", ConsoleColor.Red);
        WriteLine("                                     ", ConsoleColor.Red);
    }

    public static string MainMenu(bool fileScanAvailable, bool memoryScanAvailable)
    {
        BeginScreen("Main Menu");
        MenuItem("1", "YARA File / Disk Scan", fileScanAvailable);
        MenuItem("2", "Java Memory Signature Scan", memoryScanAvailable);
        MenuItem("3", "JVMTI / Loaded DLL Inspector");
        MenuItem("4", "Launch Script Finder");
        MenuItem("5", "Bypass Scanner");
        MenuItem("6", "External Java Class Dumper");
        MenuItem("7", "RWX Memory Scanner");
        MenuItem("8", "Credits");
        MenuItem("0", "Exit");
        Console.WriteLine();
        return PromptChoice("Choose action:", Enumerable.Range(0, 9).Select(i => i.ToString()));
    }

    public static void Section(string title)
    {
        Console.WriteLine();
        WriteLine($"── {title} ─────────────────────────────────────────", ConsoleColor.Red);
    }

    public static void Info(string text) => WriteLine($"  • {text}", ConsoleColor.Gray);
    public static void Warn(string text) => WriteLine($"  ! {text}", ConsoleColor.Yellow);
    public static void Error(string text) => WriteLine($"  ✕ {text}", ConsoleColor.Red);
    public static void Success(string text) => WriteLine($"  ✓ {text}", ConsoleColor.Green);
    public static void Dim(string text) => WriteLine(text, ConsoleColor.DarkGray);

    public static string Prompt(string text)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{text} ");
        Console.ForegroundColor = previous;
        return Console.ReadLine()?.Trim() ?? string.Empty;
    }

    public static string PromptChoice(string text, IEnumerable<string> allowed, bool allowEmpty = false)
    {
        var choices = allowed.ToHashSet(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            string value = Prompt(text);
            if ((allowEmpty && value.Length == 0) || choices.Contains(value)) return value;
            Error($"Invalid choice. Allowed: {string.Join(", ", choices.Order())}.");
        }
    }

    public static bool Confirm(string text, bool defaultValue = false)
    {
        string suffix = defaultValue ? "[Y/n]:" : "[y/N]:";
        while (true)
        {
            string value = Prompt($"{text} {suffix}").ToLowerInvariant();
            if (value.Length == 0) return defaultValue;
            if (value is "y" or "yes" or "д" or "да") return true;
            if (value is "n" or "no" or "н" or "нет") return false;
            Error("Enter y/n.");
        }
    }

    public static void Pause()
    {
        Console.WriteLine();
        Dim("  Press Enter to return to the main menu...");
        Console.ReadLine();
    }

    public static void ProgressBar(string label, ScanProgress progress)
    {
        long total = Math.Max(1, progress.TotalEstimate);
        int percent = (int)Math.Clamp(progress.BytesScanned * 100d / total, 0, 100);
        int filled = percent / 4;
        Console.Write($"\r  {label} [{new string('█', filled)}{new string('░', 25 - filled)}] {percent,3}%  {HumanBytes(progress.BytesScanned)}   ");
    }

    public static string HumanBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value:F1} {units[unit]}";
    }

    public static void RenderScanResult(ProcessDetection result)
    {
        Console.WriteLine();
        Console.WriteLine($"  Done in {result.Elapsed.TotalSeconds:F1}s. Regions: {result.RegionsScanned}. Scanned: {HumanBytes(result.BytesScanned)}.");
        if (result.Matches.Count == 0)
        {
            Success("●  CLEAN — no known signatures found");
            return;
        }

        if (result.HasConfirmed) Error("●  RED LIGHT — cheat client detected");
        else if (result.HasSuspicious) Warn("●  YELLOW LIGHT — suspicious indicators found");

        foreach (var match in result.Matches.OrderByDescending(m => m.Severity).ThenBy(m => m.Family, StringComparer.Ordinal))
        {
            var color = match.Severity == Severity.Confirmed ? ConsoleColor.Red : ConsoleColor.Yellow;
            WriteLine($"  ▸ {result.ProcessName.ToUpperInvariant()}.EXE (PID {result.ProcessId}) — {match.Family} [{match.Severity.Label()}]", color);
        }
    }

    public static void WriteLine(string text, ConsoleColor color)
    {
        var previous = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
        }
        finally
        {
            Console.ForegroundColor = previous;
        }
    }

    private static void MenuItem(string key, string label, bool enabled = true)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = enabled ? ConsoleColor.Red : ConsoleColor.DarkGray;
        Console.Write($"  {key.PadLeft(2)}  ");
        Console.ForegroundColor = enabled ? ConsoleColor.Gray : ConsoleColor.DarkGray;
        Console.WriteLine(enabled ? label : $"{label} (unavailable)");
        Console.ForegroundColor = previous;
    }
}
