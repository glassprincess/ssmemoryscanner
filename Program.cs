using System.Diagnostics;
using System.Reflection;
using Jrss.ClassDumper;
using Jrss.Core;
using Jrss.Core.YaraLite;
using Jrss.Modules;
using Jrss.Ui;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.Title = "Jrss — local anti-cheat scanner";

YaraEngine? yaraEngine = LoadYaraEngineFromAssembly();
SignatureDatabase? signatureDatabase = LoadSignatureDatabaseFromAssembly();

while (true)
{
    string choice = ConsoleUi.MainMenu(yaraEngine is not null, signatureDatabase is not null);
    ConsoleUi.Clear(); // выбранное действие всегда открывается на чистом экране

    try
    {
        switch (choice)
        {
            case "1": RunFileScan(yaraEngine); break;
            case "2": RunMemoryScan(signatureDatabase); break;
            case "3": ModuleInspector.Run(); break;
            case "4": ScriptFinder.Run(); break;
            case "5": BypassScanner.Run(); break;
            case "6": RunClassDumper(); break;
            case "7": RwxScanner.Run(); break;
            case "8": PrintCredits(); break;
            case "0":
                ConsoleUi.BeginScreen("Exiting");
                ConsoleUi.Success("Scan complete. See you.");
                return;
        }
    }
    catch (OperationCanceledException)
    {
        ConsoleUi.Warn("Operation cancelled by user.");
    }
    catch (PlatformNotSupportedException ex)
    {
        ConsoleUi.Warn(ex.Message);
    }
    catch (Exception ex)
    {
        ConsoleUi.Error($"Operation failed: {ex.Message}");
    }

    ConsoleUi.Pause();
}

static YaraEngine? LoadYaraEngineFromAssembly()
{
    try
    {
        var asm = Assembly.GetExecutingAssembly();
        var prefix = $"{asm.GetName().Name}.rules.";
        var rules = new List<YaraRule>();

        foreach (var name in asm.GetManifestResourceNames())
        {
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            if (!name.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)) continue;

            using var stream = asm.GetManifestResourceStream(name);
            if (stream is null) continue;
            using var reader = new StreamReader(stream);
            var content = reader.ReadToEnd();
            var ns = Path.GetFileNameWithoutExtension(name[prefix.Length..]);
            rules.AddRange(YaraLiteParser.ParseContent(content, ns, name));
        }

        return rules.Count == 0 ? null : YaraEngine.Compile(rules);
    }
    catch (Exception ex)
    {
        ConsoleUi.Warn($"YARA rules not loaded: {ex.Message}");
        return null;
    }
}

static SignatureDatabase? LoadSignatureDatabaseFromAssembly()
{
    try
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("signatures.json"));
        if (name is null) return null;

        using var stream = asm.GetManifestResourceStream(name);
        if (stream is null) return null;
        return SignatureDatabase.LoadFromStream(stream);
    }
    catch (Exception ex)
    {
        ConsoleUi.Warn($"Signature database not loaded: {ex.Message}");
        return null;
    }
}

static void RunMemoryScan(SignatureDatabase? database)
{
    if (database is null)
    {
        ConsoleUi.BeginScreen("Java Memory Scan");
        ConsoleUi.Warn("Signature database unavailable (not embedded in executable).");
        return;
    }
    SignatureMemoryScan.Run(database);
}

static void RunFileScan(YaraEngine? engine)
{
    ConsoleUi.BeginScreen("File / Disk Scan", "Ctrl+C safely cancels long scans.");
    if (engine is null)
    {
        ConsoleUi.Warn("YARA rules unavailable (not embedded in executable).");
        return;
    }

    string input = ConsoleUi.Prompt("Path to scan (Enter = all local drives):");
    bool scanningAllDrives = string.IsNullOrWhiteSpace(input);
    var roots = scanningAllDrives
        ? DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed).Select(d => d.RootDirectory.FullName).ToList()
        : [Path.GetFullPath(input)];

    if (roots.Count == 0 || roots.Any(root => !Directory.Exists(root) && !File.Exists(root)))
    {
        ConsoleUi.Error("Specified path does not exist or no local drives available.");
        return;
    }

    var selfPath = Environment.ProcessPath;
    var config = new ScanConfig
    {
        Roots = roots,
        SkipSigned = ConsoleUi.Confirm("Skip Authenticode-signed files?"),
        SkipPaths = selfPath is not null ? [selfPath] : null,
        MinSize = 25L * 1024,
        MaxSize = 50L * 1024 * 1024,
    };

    using var cancellation = new CancellationTokenSource();
    ConsoleCancelEventHandler handler = (_, args) =>
    {
        args.Cancel = true;
        cancellation.Cancel();
    };
    Console.CancelKeyPress += handler;

    try
    {
        var scanner = new FileScanner(engine);
        var stats = new ScanStats();
        int detections = 0;
        var stopwatch = Stopwatch.StartNew();

        foreach (var detection in scanner.Scan(config, stats, cancellation.Token, _ =>
                 {
                     if (stats.Processed % 200 == 0)
                          Console.Write($"\r  Processed: {stats.Processed}; scanned: {stats.Scanned}; detections: {detections}   ");
                 }))
        {
            detections++;
            Console.WriteLine();
            ConsoleUi.Error($"DETECTION: {detection.Path} → {detection.Namespace}/{detection.RuleName} ({detection.Matched}/{detection.Total})");
            if (scanningAllDrives) break;
        }

        Console.WriteLine();
        ConsoleUi.Info($"Done in {stopwatch.Elapsed.TotalSeconds:F1}s: processed {stats.Processed}, scanned {stats.Scanned}, errors {stats.Errors}, detections {detections}.");
        if (detections == 0) ConsoleUi.Success("No matches against known YARA rules found.");
    }
    finally
    {
        Console.CancelKeyPress -= handler;
    }
}

static void RunClassDumper()
{
    ConsoleUi.BeginScreen("External Java Class Dumper", "Uses standard Java Attach API, like VisualVM and jcmd.");
    using var process = JavaProcesses.Pick();
    if (process is null) return;

    string outputDirectory = Path.Combine(Environment.CurrentDirectory, $"class-dump-{process.Id}");
    ConsoleUi.Info($"PID {process.Id}; output: {outputDirectory}");
    var (ok, message) = ExternalClassDumper.Dump(process.Id, outputDirectory);
    if (ok) ConsoleUi.Success(message); else ConsoleUi.Error(message);
}

static void PrintCredits()
{
    ConsoleUi.BeginScreen("Credits");
    Console.WriteLine("  Jrss — local anti-cheat toolkit for screenshare inspections.");
    Console.WriteLine("  Written and maintained by Lain.");
    Console.WriteLine();
    Console.WriteLine("  Modules: YARA file/disk scanner, Java memory signature scan,");
    Console.WriteLine("  JVMTI/injection inspector, RWX scanner, launch script finder, bypass scanner, and class dumper.");
    Console.WriteLine();
    ConsoleUi.WriteLine("  Discord: rewakura", ConsoleColor.Red);
}
