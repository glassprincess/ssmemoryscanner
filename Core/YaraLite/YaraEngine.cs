using System.Buffers.Binary;

namespace Jrss.Core.YaraLite;

public sealed class YaraEngine
{
    public IReadOnlyList<YaraRule> Rules { get; }

    private readonly AhoCorasick<(int ruleIdx, int stringIdx)> _sensitiveAutomaton;
    private readonly AhoCorasick<(int ruleIdx, int stringIdx)> _nocaseAutomaton;
    private readonly int _headerLength;

    private YaraEngine(
        List<YaraRule> rules,
        AhoCorasick<(int, int)> sensitiveAutomaton,
        AhoCorasick<(int, int)> nocaseAutomaton,
        int headerLength)
    {
        Rules = rules;
        _sensitiveAutomaton = sensitiveAutomaton;
        _nocaseAutomaton = nocaseAutomaton;
        _headerLength = headerLength;
    }

    public static YaraEngine Compile(List<YaraRule> rules)
    {
        var sensitiveAutomaton = new AhoCorasick<(int, int)>();
        var nocaseAutomaton = new AhoCorasick<(int, int)>();
        long requestedHeaderLength = 0;

        for (int ruleIdx = 0; ruleIdx < rules.Count; ruleIdx++)
        {
            var rule = rules[ruleIdx];
            requestedHeaderLength = Math.Max(requestedHeaderLength, GetRequiredHeaderLength(rule.Condition));
            for (int stringIdx = 0; stringIdx < rule.Strings.Count; stringIdx++)
            {
                var yaraString = rule.Strings[stringIdx];
                var automaton = yaraString.Nocase ? nocaseAutomaton : sensitiveAutomaton;
                var bytes = yaraString.Nocase ? ToAsciiLower(yaraString.Bytes) : yaraString.Bytes;

                if (yaraString.Ascii)
                {
                    automaton.AddPattern(bytes, (ruleIdx, stringIdx));
                }
                if (yaraString.Wide)
                {
                    automaton.AddPattern(ToWide(bytes), (ruleIdx, stringIdx));
                }
            }
        }

        if (requestedHeaderLength > int.MaxValue)
        {
            throw new NotSupportedException("The YARA rule reads beyond the supported header size.");
        }

        sensitiveAutomaton.Build();
        nocaseAutomaton.Build();
        return new YaraEngine(rules, sensitiveAutomaton, nocaseAutomaton, (int)requestedHeaderLength);
    }

    /// <summary>Scans a complete in-memory input.</summary>
    public List<RuleMatch> ScanBuffer(ReadOnlySpan<byte> buffer)
    {
        var hits = new HashSet<(int ruleIdx, int stringIdx)>();
        _sensitiveAutomaton.Scan(buffer, tag => hits.Add(tag));
        _nocaseAutomaton.Scan(buffer, tag => hits.Add(tag), asciiCaseInsensitive: true);
        return Finalize(hits, buffer, buffer.Length);
    }

    /// <summary>
    /// Scans a stream in chunks. Automaton state is preserved between chunks, so strings
    /// spanning a chunk boundary are found without scanning any bytes twice.
    /// </summary>
    public List<RuleMatch> ScanStream(Stream stream, int chunkSize = 4 * 1024 * 1024)
    {
        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize));
        }

        var hits = new HashSet<(int ruleIdx, int stringIdx)>();
        var buffer = new byte[chunkSize];
        var header = _headerLength == 0 ? Array.Empty<byte>() : new byte[_headerLength];
        int capturedHeader = 0;
        long length = 0;
        int sensitiveState = _sensitiveAutomaton.InitialState;
        int nocaseState = _nocaseAutomaton.InitialState;

        while (true)
        {
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                break;
            }

            var chunk = buffer.AsSpan(0, read);
            if (capturedHeader < header.Length)
            {
                int copy = Math.Min(header.Length - capturedHeader, read);
                chunk[..copy].CopyTo(header.AsSpan(capturedHeader));
                capturedHeader += copy;
            }

            sensitiveState = _sensitiveAutomaton.ScanChunk(sensitiveState, chunk, tag => hits.Add(tag));
            nocaseState = _nocaseAutomaton.ScanChunk(
                nocaseState, chunk, tag => hits.Add(tag), asciiCaseInsensitive: true);
            length = checked(length + read);
        }

        return Finalize(hits, header.AsSpan(0, capturedHeader), length);
    }

    private List<RuleMatch> Finalize(
        HashSet<(int ruleIdx, int stringIdx)> hits,
        ReadOnlySpan<byte> header,
        long length)
    {
        var results = new List<RuleMatch>();
        for (int ruleIdx = 0; ruleIdx < Rules.Count; ruleIdx++)
        {
            var rule = Rules[ruleIdx];
            var matchedIds = new HashSet<string>(StringComparer.Ordinal);
            for (int stringIdx = 0; stringIdx < rule.Strings.Count; stringIdx++)
            {
                if (hits.Contains((ruleIdx, stringIdx)))
                {
                    matchedIds.Add(rule.Strings[stringIdx].Id);
                }
            }

            bool confirmed = YaraConditionEvaluator.Evaluate(rule.Condition, matchedIds, rule.Strings, header, length);
            if (matchedIds.Count == 0 && !confirmed)
            {
                continue;
            }

            results.Add(new RuleMatch
            {
                Namespace = rule.Namespace,
                RuleName = rule.Name,
                Matched = matchedIds.Count,
                Total = rule.Strings.Count,
                Confirmed = confirmed,
            });
        }
        return results;
    }

    private static byte[] ToWide(ReadOnlySpan<byte> bytes)
    {
        var wide = new byte[checked(bytes.Length * 2)];
        for (int i = 0; i < bytes.Length; i++)
        {
            wide[i * 2] = bytes[i];
        }
        return wide;
    }

    private static byte[] ToAsciiLower(ReadOnlySpan<byte> bytes)
    {
        var normalized = bytes.ToArray();
        for (int i = 0; i < normalized.Length; i++)
        {
            if (normalized[i] is >= (byte)'A' and <= (byte)'Z')
            {
                normalized[i] = (byte)(normalized[i] + ('a' - 'A'));
            }
        }
        return normalized;
    }

    private static long GetRequiredHeaderLength(YaraCondition condition) => condition switch
    {
        YaraUInt16Condition { Offset: var offset } => checked(offset + sizeof(ushort)),
        YaraAndCondition(var left, var right) => Math.Max(GetRequiredHeaderLength(left), GetRequiredHeaderLength(right)),
        YaraOrCondition(var left, var right) => Math.Max(GetRequiredHeaderLength(left), GetRequiredHeaderLength(right)),
        YaraNotCondition(var operand) => GetRequiredHeaderLength(operand),
        _ => 0,
    };
}

internal static class YaraConditionEvaluator
{
    public static bool Evaluate(
        YaraCondition condition,
        HashSet<string> matchedIds,
        IReadOnlyList<YaraString> strings,
        ReadOnlySpan<byte> header,
        long fileSize)
    {
        return condition switch
        {
            YaraBooleanCondition(var value) => value,
            YaraStringCondition(var id) => matchedIds.Contains(id),
            YaraAndCondition(var left, var right) =>
                Evaluate(left, matchedIds, strings, header, fileSize) && Evaluate(right, matchedIds, strings, header, fileSize),
            YaraOrCondition(var left, var right) =>
                Evaluate(left, matchedIds, strings, header, fileSize) || Evaluate(right, matchedIds, strings, header, fileSize),
            YaraNotCondition(var operand) => !Evaluate(operand, matchedIds, strings, header, fileSize),
            YaraOfCondition(var kind, var count, var selectors) => EvaluateOf(kind, count, selectors, matchedIds, strings),
            YaraUInt16Condition(var offset, var comparison, var value) =>
                offset >= 0 && offset <= header.Length - sizeof(ushort) &&
                Compare(BinaryPrimitives.ReadUInt16LittleEndian(header.Slice((int)offset, sizeof(ushort))), comparison, value),
            YaraFileSizeCondition(var comparison, var value) => Compare(fileSize, comparison, value),
            _ => throw new NotSupportedException($"Unsupported YARA condition: {condition.GetType().Name}"),
        };
    }

    private static bool EvaluateOf(
        YaraOfKind kind,
        int count,
        IReadOnlyList<YaraStringSelector>? selectors,
        HashSet<string> matchedIds,
        IReadOnlyList<YaraString> strings)
    {
        var selected = new HashSet<string>(StringComparer.Ordinal);
        if (selectors is null)
        {
            foreach (var yaraString in strings) selected.Add(yaraString.Id);
        }
        else
        {
            foreach (var selector in selectors)
            {
                foreach (var yaraString in strings)
                {
                    bool selectedByPattern = selector.IsWildcard
                        ? yaraString.Id.StartsWith(selector.IdOrPrefix, StringComparison.Ordinal)
                        : yaraString.Id.Equals(selector.IdOrPrefix, StringComparison.Ordinal);
                    if (selectedByPattern) selected.Add(yaraString.Id);
                }
            }
        }

        int matched = selected.Count(matchedIds.Contains);
        return kind switch
        {
            YaraOfKind.Count => matched >= count,
            YaraOfKind.Any => matched > 0,
            YaraOfKind.All => matched == selected.Count,
            YaraOfKind.None => matched == 0,
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
    }

    private static bool Compare(long actual, YaraComparison comparison, long expected) => comparison switch
    {
        YaraComparison.Equal => actual == expected,
        YaraComparison.NotEqual => actual != expected,
        YaraComparison.Less => actual < expected,
        YaraComparison.LessOrEqual => actual <= expected,
        YaraComparison.Greater => actual > expected,
        YaraComparison.GreaterOrEqual => actual >= expected,
        _ => throw new ArgumentOutOfRangeException(nameof(comparison)),
    };
}
