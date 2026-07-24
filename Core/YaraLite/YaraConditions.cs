namespace Jrss.Core.YaraLite;

/// <summary>Subset of YARA conditions used by the bundled rules.</summary>
public abstract record YaraCondition;

public sealed record YaraBooleanCondition(bool Value) : YaraCondition;
public sealed record YaraStringCondition(string Id) : YaraCondition;
public sealed record YaraAndCondition(YaraCondition Left, YaraCondition Right) : YaraCondition;
public sealed record YaraOrCondition(YaraCondition Left, YaraCondition Right) : YaraCondition;
public sealed record YaraNotCondition(YaraCondition Operand) : YaraCondition;
public sealed record YaraOfCondition(YaraOfKind Kind, int Count, IReadOnlyList<YaraStringSelector>? Selectors) : YaraCondition;
public sealed record YaraUInt16Condition(long Offset, YaraComparison Comparison, ushort Value) : YaraCondition;
public sealed record YaraFileSizeCondition(YaraComparison Comparison, long Value) : YaraCondition;

public sealed record YaraStringSelector(string IdOrPrefix, bool IsWildcard);

public enum YaraOfKind
{
    Count,
    Any,
    All,
    None,
}

public enum YaraComparison
{
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}
