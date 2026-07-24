using System.Security.Cryptography.X509Certificates;
using Jrss.Core.YaraLite;

namespace Jrss.Core;

public sealed class ScanConfig
{
    public required List<string> Roots { get; init; }
    public long? MinSize { get; init; }
    public long? MaxSize { get; init; }
    public bool SkipSigned { get; init; }
    public HashSet<string>? Extensions { get; init; }
}

public sealed class FileDetection
{
    public required string Path { get; init; }
    public required string Namespace { get; init; }
    public required string RuleName { get; init; }
    public required int Matched { get; init; }
    public required int Total { get; init; }
}

public sealed class ScanStats
{
    public long Processed;
    public long Scanned;
    public long SkippedSize;
    public long SkippedSigned;
    public long Errors;
}

/// <summary>
/// Обходит заданные корни (диски/папки), фильтрует по размеру/расширению,
/// опционально пропускает подписанные (Authenticode) файлы, и прогоняет
/// содержимое через YaraEngine. По духу — то же самое, что делает
/// scanner.rs/defender.rs в LoaderChecker, просто на .NET.
/// </summary>
public sealed class FileScanner
{
    private readonly YaraEngine _engine;

    public FileScanner(YaraEngine engine)
    {
        _engine = engine;
    }

    public IEnumerable<FileDetection> Scan(
        ScanConfig cfg,
        ScanStats stats,
        CancellationToken cancellationToken = default,
        Action<string>? onFile = null)
    {
        foreach (var root in cfg.Roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IEnumerable<string> files;
            try
            {
                files = EnumerateFiles(root);
            }
            catch
            {
                continue;
            }

            foreach (var path in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                stats.Processed++;
                onFile?.Invoke(path);

                FileInfo info;
                try
                {
                    info = new FileInfo(path);
                }
                catch
                {
                    stats.Errors++;
                    continue;
                }

                if (cfg.Extensions is { Count: > 0 } &&
                    !cfg.Extensions.Contains(info.Extension.TrimStart('.').ToLowerInvariant()))
                {
                    continue;
                }

                if ((cfg.MinSize.HasValue && info.Length < cfg.MinSize.Value) ||
                    (cfg.MaxSize.HasValue && info.Length > cfg.MaxSize.Value))
                {
                    stats.SkippedSize++;
                    continue;
                }

                if (cfg.SkipSigned && IsAuthenticodeSigned(path))
                {
                    stats.SkippedSigned++;
                    continue;
                }

                List<RuleMatch> matches;
                try
                {
                    using var fs = File.OpenRead(path);
                    matches = _engine.ScanStream(fs);
                    stats.Scanned++;
                }
                catch
                {
                    stats.Errors++;
                    continue;
                }

                foreach (var m in matches.Where(m => m.Confirmed))
                {
                    yield return new FileDetection
                    {
                        Path = path,
                        Namespace = m.Namespace,
                        RuleName = m.RuleName,
                        Matched = m.Matched,
                        Total = m.Total,
                    };
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> subdirs = Array.Empty<string>();
            IEnumerable<string> filesHere = Array.Empty<string>();

            try
            {
                subdirs = Directory.EnumerateDirectories(dir);
                filesHere = Directory.EnumerateFiles(dir);
            }
            catch
            {
                // нет прав / диск отвалился — просто пропускаем эту ветку
            }

            foreach (var f in filesHere)
            {
                yield return f;
            }
            foreach (var d in subdirs)
            {
                stack.Push(d);
            }
        }
    }

    /// <summary>
    /// Authenticode-проверка через встроенный .NET API — без P/Invoke WinVerifyTrust.
    /// Не идеальна (не проверяет цепочку доверия до конца), но для "пропустить явно
    /// подписанные файлы и ускорить скан" этого достаточно, как и в LoaderChecker.
    /// </summary>
    private static bool IsAuthenticodeSigned(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return cert is not null;
        }
        catch
        {
            return false;
        }
    }
}
