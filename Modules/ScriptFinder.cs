using System.Text;
using Jrss.Ui;

namespace Jrss.Modules;

internal static class ScriptFinder
{
    private static readonly string[] InterestingPrefetchPrefixes =
    [
        "CMD.EXE", "POWERSHELL.EXE", "PWSH.EXE", "PYTHON.EXE", "PYTHONW.EXE",
        "WSCRIPT.EXE", "CSCRIPT.EXE", "MSHTA.EXE", "AUTOHOTKEY.EXE",
        "AUTOHOTKEYU64.EXE", "AUTOHOTKEYA32.EXE", "AUTOHOTKEYUX.EXE",
    ];

    private static readonly string[] DownloadPatterns =
    ["invoke-webrequest", "iwr ", "invoke-restmethod", "downloadstring", "downloadfile", "curl ", "wget ", "bitsadmin", "certutil -urlcache"];
    private static readonly string[] DeletionPatterns =
    ["remove-item -recurse -force", "rm -r -force", "del /f /s /q", "clear-history", "wevtutil cl", "vssadmin delete shadows", "fsutil usn deletejournal", "cipher /w"];
    private static readonly string[] EvasionPatterns =
    ["-encodedcommand", "-enc ", "-windowstyle hidden", "-w hidden", "-executionpolicy bypass", "-ep bypass", "set-mppreference -disablerealtimemonitoring", "add-mppreference -exclusionpath"];
    private static readonly string[] AhkInjectionSignals =
    ["winhttp.winhttprequest", "adodb.stream", "virtualallocex", "writeprocessmemory", "createremotethread", "resumethread", "virtualprotectex", "createprocessw", "comobjvalue"];

    private const int MaxDepth = 5;
    private const int MaxFiles = 500;
    private const int InjectionThreshold = 5;
    private const double SimilarityThreshold = 0.30;

    public static void Run()
    {
        ConsoleUi.Section("Launch Script Finder");
        ConsoleUi.Info("Prefetch: cmd/powershell/python/wscript/cscript/mshta/AutoHotkey.");
        ConsoleUi.Info("Это не доказательство читерства само по себе: такие интерпретаторы используются и легитимно.");

        string prefetchDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetchDirectory))
        {
            ConsoleUi.Warn("Папка Prefetch недоступна: нет прав, она отключена или система не Windows.");
            return;
        }

        var hits = new List<(string Name, DateTime? Modified)>();
        bool sawAhk = false;
        bool sawPython = false;
        try
        {
            foreach (var file in Directory.EnumerateFiles(prefetchDirectory))
            {
                string name = Path.GetFileName(file).ToUpperInvariant();
                if (!InterestingPrefetchPrefixes.Any(prefix => name.StartsWith(prefix, StringComparison.Ordinal)))
                {
                    continue;
                }

                sawAhk |= name.StartsWith("AUTOHOTKEY", StringComparison.Ordinal);
                sawPython |= name.StartsWith("PYTHON", StringComparison.Ordinal);
                DateTime? modified = null;
                try { modified = File.GetLastWriteTime(file); } catch { }
                hits.Add((Path.GetFileName(file), modified));
            }
        }
        catch (UnauthorizedAccessException)
        {
            ConsoleUi.Warn("Папка Prefetch недоступна: недостаточно прав.");
            return;
        }

        if (hits.Count == 0)
        {
            ConsoleUi.Success("Подозрительных Prefetch-записей не найдено.");
        }
        else
        {
            foreach (var hit in hits.OrderBy(hit => hit.Name, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"  ▸ {hit.Name} ({hit.Modified?.ToString("G") ?? "время неизвестно"})");
            }
            ConsoleUi.Warn($"Найдено записей: {hits.Count}. Сверь их с историей действий игрока за скриншер.");
        }

        ConsoleUi.Section("История PowerShell");
        CheckPowerShellHistory();

        if (sawAhk)
        {
            ConsoleUi.Section("Найден запуск AutoHotkey — поиск .ahk-файлов");
            ScanScriptsAndCompare("ahk", "ahk");
        }
        if (sawPython)
        {
            ConsoleUi.Section("Найден запуск Python — поиск .py-файлов");
            ScanScriptsAndCompare("py", "py");
        }
    }

    private static void CheckPowerShellHistory()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrWhiteSpace(appData))
        {
            ConsoleUi.Warn("Переменная APPDATA недоступна — история PowerShell пропущена.");
            return;
        }

        string historyPath = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
        string content;
        try
        {
            content = File.ReadAllText(historyPath);
        }
        catch
        {
            ConsoleUi.Info("Файл истории PowerShell не найден: не использовался или очищен.");
            return;
        }

        string lower = content.ToLowerInvariant();
        int downloads = CountOccurrences(lower, DownloadPatterns);
        int deletions = CountOccurrences(lower, DeletionPatterns);
        int evasion = CountOccurrences(lower, EvasionPatterns);
        int total = downloads + deletions + evasion;
        Console.WriteLine($"  Загрузки/импорты: {downloads}   Удаления/очистки: {deletions}   Обход защиты: {evasion}");

        if (total == 0)
        {
            ConsoleUi.Success("Подозрительных команд в истории PowerShell не найдено.");
        }
        else if (total < 3)
        {
            ConsoleUi.Info("Есть единичные подозрительные команды — это шум, но стоит держать на заметке.");
        }
        else
        {
            ConsoleUi.Warn($"В истории найдено подозрительных команд: {total}. Похоже на массовую загрузку или чистку следов.");
        }
    }

    private static int CountOccurrences(string content, IEnumerable<string> patterns) =>
        patterns.Sum(pattern => CountOccurrences(content, pattern));

    private static int CountOccurrences(string content, string pattern)
    {
        int count = 0;
        int index = 0;
        while ((index = content.IndexOf(pattern, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += pattern.Length;
        }
        return count;
    }

    private static void ScanScriptsAndCompare(string extension, string referenceSubdirectory)
    {
        string referenceDirectory = Path.Combine(AppContext.BaseDirectory, "data", "reference_scripts", referenceSubdirectory);
        if (!Directory.Exists(referenceDirectory))
        {
            ConsoleUi.Warn($"Нет эталонов в data/reference_scripts/{referenceSubdirectory}/: сравнение пропущено.");
            return;
        }

        var found = new List<string>();
        foreach (var directory in CommonUserDirectories())
        {
            WalkForExtension(directory, extension, found);
            if (found.Count >= MaxFiles) break;
        }
        if (found.Count == 0)
        {
            ConsoleUi.Info($"Файлов .{extension} в пользовательских директориях не найдено.");
            return;
        }

        ConsoleUi.Info($"Найдено файлов .{extension}: {found.Count}; сверяю с эталонами и паттернами.");
        bool anyMatch = false;
        bool anySignal = false;
        foreach (var candidate in found)
        {
            var matches = CompareAgainstReferences(candidate, referenceDirectory);
            if (matches.Count > 0)
            {
                anyMatch = true;
                var best = matches[0];
                ConsoleUi.Warn($"▸ {candidate} — похож на эталон «{best.Name}», схожесть {best.Similarity:P0}");
            }

            if (extension == "ahk")
            {
                try
                {
                    int signals = CountInjectionSignals(File.ReadAllText(candidate));
                    if (signals >= InjectionThreshold)
                    {
                        anySignal = true;
                        ConsoleUi.Warn($"▸ {candidate} — паттерн загрузчика с процесс-инъекцией ({signals}/{AhkInjectionSignals.Length} технических сигналов)");
                    }
                }
                catch { }
            }
        }

        if (!anyMatch && !anySignal)
        {
            ConsoleUi.Success($"Ни один .{extension}-файл не похож на известные эталоны или паттерны.");
        }
    }

    private static IEnumerable<string> CommonUserDirectories()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(profile)) yield break;
        yield return Path.Combine(profile, "Desktop");
        yield return Path.Combine(profile, "Downloads");
        yield return Path.Combine(profile, "Documents");
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        yield return Path.GetTempPath();
    }

    private static void WalkForExtension(string root, string extension, List<string> output)
    {
        if (!Directory.Exists(root) || output.Count >= MaxFiles) return;
        var pending = new Stack<(string Directory, int Depth)>();
        pending.Push((root, 0));
        while (pending.Count > 0 && output.Count < MaxFiles)
        {
            var (directory, depth) = pending.Pop();
            IEnumerable<string> entries;
            try { entries = Directory.EnumerateFileSystemEntries(directory); }
            catch { continue; }

            foreach (var entry in entries)
            {
                if (output.Count >= MaxFiles) return;
                try
                {
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (depth < MaxDepth) pending.Push((entry, depth + 1));
                    }
                    else if (Path.GetExtension(entry).Equals($".{extension}", StringComparison.OrdinalIgnoreCase))
                    {
                        output.Add(entry);
                    }
                }
                catch { }
            }
        }
    }

    private static List<(string Name, double Similarity)> CompareAgainstReferences(string candidate, string referenceDirectory)
    {
        HashSet<string> candidateLines;
        try { candidateLines = NormalizedLines(File.ReadAllText(candidate)); }
        catch { return []; }
        if (candidateLines.Count == 0) return [];

        var matches = new List<(string Name, double Similarity)>();
        foreach (var reference in Directory.EnumerateFiles(referenceDirectory))
        {
            try
            {
                double similarity = JaccardSimilarity(candidateLines, NormalizedLines(File.ReadAllText(reference)));
                if (similarity >= SimilarityThreshold)
                {
                    matches.Add((Path.GetFileName(reference), similarity));
                }
            }
            catch { }
        }
        return matches.OrderByDescending(match => match.Similarity).ToList();
    }

    private static int CountInjectionSignals(string content)
    {
        string lower = content.ToLowerInvariant();
        return AhkInjectionSignals.Count(signal => lower.Contains(signal, StringComparison.Ordinal));
    }

    private static HashSet<string> NormalizedLines(string content) =>
        content.Split('\n')
            .Select(NormalizeLine)
            .Where(line => !string.IsNullOrEmpty(line) && !line.StartsWith(';') && !line.StartsWith('#'))
            .ToHashSet(StringComparer.Ordinal);

    private static string NormalizeLine(string line)
    {
        var output = new StringBuilder();
        var token = new StringBuilder();
        foreach (char character in line.Trim())
        {
            if (char.IsLetterOrDigit(character) || character == '_')
            {
                token.Append(character);
            }
            else
            {
                FlushToken(token, output);
                output.Append(character);
            }
        }
        FlushToken(token, output);
        return output.ToString();
    }

    private static void FlushToken(StringBuilder token, StringBuilder output)
    {
        if (token.Length == 0) return;
        string value = token.ToString();
        output.Append(LooksLikeRandomIdentifier(value) ? "VAR" : value.ToLowerInvariant());
        token.Clear();
    }

    private static bool LooksLikeRandomIdentifier(string word) =>
        word.Length >= 6 &&
        word.Any(character => character is >= 'A' and <= 'Z') &&
        word.Any(character => character is >= 'a' and <= 'z') &&
        word.Any(character => character is >= '0' and <= '9');

    private static double JaccardSimilarity(HashSet<string> left, HashSet<string> right)
    {
        if (left.Count == 0 || right.Count == 0) return 0;
        int intersection = left.Intersect(right).Count();
        int union = left.Union(right).Count();
        return union == 0 ? 0 : (double)intersection / union;
    }
}
