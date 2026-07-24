namespace Jrss.Core;

public enum Severity
{
    Suspicious,
    Confirmed,
}

public static class SeverityExtensions
{
    public static string Label(this Severity severity) => severity switch
    {
        Severity.Confirmed => "CONFIRMED",
        Severity.Suspicious => "SUSPICIOUS",
        _ => severity.ToString(),
    };
}

public sealed class SignatureFamily
{
    public required string Family { get; init; }
    public required Severity Severity { get; init; }
    public required List<string> Patterns { get; init; }
}

public sealed record DetectionTag(string Family, Severity Severity);

public sealed class ProcessDetection
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public HashSet<DetectionTag> Matches { get; } = new();
    public long BytesScanned { get; internal set; }
    public int RegionsScanned { get; internal set; }
    public TimeSpan Elapsed { get; internal set; }

    public bool HasConfirmed => Matches.Any(m => m.Severity == Severity.Confirmed);
    public bool HasSuspicious => Matches.Any(m => m.Severity == Severity.Suspicious);
}

public readonly record struct ScanProgress(long BytesScanned, long TotalEstimate, int RegionsDone, int RegionsTotal);
