namespace Jrss.Core.YaraLite;

public sealed class YaraString
{
    public required string Id { get; init; }
    public required byte[] Bytes { get; init; }
    public bool Ascii { get; init; }
    public bool Wide { get; init; }
    public bool Nocase { get; init; }
}

public sealed class YaraRule
{
    public required string Namespace { get; init; }
    public required string Name { get; init; }
    public required List<YaraString> Strings { get; init; }
    /// <summary>Parsed YARA condition. The rule is reported only when this expression is true.</summary>
    public required YaraCondition Condition { get; init; }
    public string? RawCondition { get; init; }
}

public sealed class RuleMatch
{
    public required string Namespace { get; init; }
    public required string RuleName { get; init; }
    public required int Matched { get; init; }
    public required int Total { get; init; }
    public required bool Confirmed { get; init; }
}
