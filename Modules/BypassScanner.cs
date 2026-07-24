using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Jrss.Ui;

namespace Jrss.Modules;

internal static class BypassScanner
{
    private static readonly string[] BlockedSites =
    [
        "anticheat.ac", "mods.holyworld.me", "github.com", "voidtools.com",
        "privazer.com", "nirsoft.net", "sourceforge.net",
        "download.ericzimmermanstools.com", "win-rar.com", "simpleunlocker.ds1nc.ru"
    ];

    private static readonly string[] CriticalServices = ["PcaSVC", "DPS", "SysMain", "EventLog", "bam"];

    private readonly record struct BypassOutcome(bool Triggered, string Details)
    {
        public static BypassOutcome Clean(string details) => new(false, details);
        public static BypassOutcome Flagged(string details) => new(true, details);
    }

    public static void Run()
    {
        if (!OperatingSystem.IsWindows())
        {
            ConsoleUi.Warn("Bypass-сканер доступен только на Windows.");
            return;
        }

        ConsoleUi.Section("Bypass-сканер");
        ConsoleUi.Info("Ищем следы заметания улик перед скриншером. Каждый индикатор требует ручной оценки.");

        var detectors = new (string Name, Func<BypassOutcome> Check)[]
        {
            ("Блокировка анти-чит сайтов", CheckSiteBlocking),
            ("Статус служб (PcaSVC/DPS/SysMain/EventLog/bam)", CheckCriticalServices),
            ("Очистка журнала Security", CheckSecurityLogClear),
            ("USN Journal", CheckUsnJournal),
            ("Теневые копии (VSS)", CheckShadowCopies),
        };

        int flagged = 0;
        foreach (var detector in detectors)
        {
            try
            {
                var outcome = detector.Check();
                if (outcome.Triggered)
                {
                    flagged++;
                    ConsoleUi.Warn($"{detector.Name} — {outcome.Details}");
                }
                else
                {
                    ConsoleUi.Success($"{detector.Name} — {outcome.Details}");
                }
            }
            catch (Exception ex)
            {
                ConsoleUi.Error($"{detector.Name} — ошибка проверки: {ex.Message}");
            }
        }

        if (flagged == 0)
        {
            ConsoleUi.Success("Явных следов заметания улик не найдено.");
        }
        else
        {
            ConsoleUi.Warn($"Сработало индикаторов: {flagged}. Это повод присмотреться внимательнее, но не автоматический детект чита.");
        }
    }

    private static BypassOutcome CheckSiteBlocking()
    {
        var blocked = new List<string>();
        string hostsContent;
        try
        {
            hostsContent = File.ReadAllText(Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts"));
        }
        catch
        {
            hostsContent = "";
        }

        var hostsLines = hostsContent.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToArray();

        foreach (var site in BlockedSites)
        {
            var reasons = new List<string>();

            if (hostsLines.Any(l => l.Contains(site, StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add("HOSTS");
            }

            try
            {
                var addresses = System.Net.Dns.GetHostAddresses(site);
                if (addresses.Any(a => a.ToString().StartsWith("127.") || a.Equals(System.Net.IPAddress.Loopback) || a.Equals(System.Net.IPAddress.IPv6Loopback)))
                {
                    reasons.Add("DNS_LOOPBACK");
                }
            }
            catch { }

            if (reasons.Count > 0)
            {
                blocked.Add($"{site} → {string.Join(", ", reasons)}");
            }
        }

        return blocked.Count == 0
            ? BypassOutcome.Clean($"нет блокировок среди {BlockedSites.Length} проверенных сайтов")
            : BypassOutcome.Flagged($"обнаружена блокировка сайтов:{string.Concat(blocked.Select(b => "\n    ▸ " + b))}");
    }

    private static BypassOutcome CheckCriticalServices()
    {
        DateTime bootTime = GetBootTime();
        var issues = new List<string>();

        foreach (var serviceName in CriticalServices)
        {
            var output = RunCommand("sc", "queryex", serviceName);
            if (output is null)
            {
                issues.Add($"{serviceName}: sc недоступен");
                continue;
            }

            string text = output.Value.StandardOutput;
            bool running = text.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);

            if (!running)
            {
                issues.Add($"{serviceName}: НЕ ЗАПУЩЕН");
                continue;
            }

            var pidMatch = Regex.Match(text, @"PID\s*:\s*(\d+)", RegexOptions.IgnoreCase);
            if (!pidMatch.Success || !int.TryParse(pidMatch.Groups[1].Value, out int pid) || pid == 0)
            {
                continue;
            }

            try
            {
                var proc = Process.GetProcessById(pid);
                TimeSpan diff = proc.StartTime - bootTime;
                if (Math.Abs(diff.TotalSeconds) > 10)
                {
                    issues.Add($"{serviceName}: запущен через {diff.TotalSeconds:F0}с после загрузки (допустимо ≤ 10с)");
                }
            }
            catch { }
        }

        return issues.Count == 0
            ? BypassOutcome.Clean("все службы запущены и стартовали вовремя")
            : BypassOutcome.Flagged(string.Join("; ", issues));
    }

    private static DateTime GetBootTime()
    {
        return DateTime.UtcNow.AddMilliseconds(-Environment.TickCount64).ToLocalTime();
    }

    private static BypassOutcome CheckSecurityLogClear()
    {
        var output = RunCommand("wevtutil", "qe", "Security", "/q:*[System[(EventID=1102)]]", "/c:1", "/f:text");
        if (output is null) return BypassOutcome.Clean("wevtutil недоступен: пропущено");
        return string.IsNullOrWhiteSpace(output.Value.StandardOutput)
            ? BypassOutcome.Clean("следов очистки журнала Security не найдено")
            : BypassOutcome.Flagged("найдено событие 1102: журнал Security когда-то очищался");
    }

    private static BypassOutcome CheckUsnJournal()
    {
        var output = RunCommand("fsutil", "usn", "queryjournal", "C:");
        if (output is null) return BypassOutcome.Clean("fsutil недоступен: пропущено");
        string text = (output.Value.StandardOutput + output.Value.StandardError).ToLowerInvariant();
        return output.Value.ExitCode != 0 || text.Contains("journal is not active", StringComparison.Ordinal)
            ? BypassOutcome.Flagged("USN Journal на диске C: не активен: возможно, был удалён или пересоздан")
            : BypassOutcome.Clean("USN Journal активен");
    }

    private static BypassOutcome CheckShadowCopies()
    {
        var output = RunCommand("vssadmin", "list", "shadows");
        if (output is null) return BypassOutcome.Clean("vssadmin недоступен: пропущено");
        string text = output.Value.StandardOutput.ToLowerInvariant();
        return text.Contains("no items found", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(text)
            ? BypassOutcome.Flagged("теневых копий не найдено: информационно, не всегда признак зачистки")
            : BypassOutcome.Clean("теневые копии присутствуют");
    }

    private static (int ExitCode, string StandardOutput, string StandardError)? RunCommand(string fileName, params string[] arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo(fileName)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
            using var process = Process.Start(startInfo);
            if (process is null) return null;
            string standardOutput = process.StandardOutput.ReadToEnd();
            string standardError = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, standardOutput, standardError);
        }
        catch
        {
            return null;
        }
    }
}
