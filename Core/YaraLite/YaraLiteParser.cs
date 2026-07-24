using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Jrss.Core.YaraLite;

/// <summary>
/// Parses the textual-string and condition constructs used by the bundled YARA rules.
/// Unsupported syntax fails at load time instead of being silently interpreted as a
/// different rule.
/// </summary>
public static class YaraLiteParser
{
    private static readonly Regex RuleStartRegex = new(
        @"(?im)\b(?:(?:private|global)\s+)*rule\s+(?<name>[A-Za-z_]\w*)\s*(?::[^\{]+)?\{",
        RegexOptions.Compiled);

    private static readonly Regex StringsSectionRegex = new(
        @"\bstrings\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ConditionSectionRegex = new(
        @"\bcondition\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex StringDefinitionRegex = new(
        @"\$(?<id>[A-Za-z_]\w*)\s*=\s*""(?<value>(?:[^""\\]|\\.)*)""(?<mods>(?:\s+[A-Za-z_]\w*(?:\([^)]*\))?)*)",
        RegexOptions.Compiled);

    private static readonly Regex ModifierRegex = new(
        @"[A-Za-z_]\w*", RegexOptions.Compiled);

    public static List<YaraRule> ParseFile(string path)
    {
        return ParseContent(File.ReadAllText(path), Path.GetFileNameWithoutExtension(path), path);
    }

    public static List<YaraRule> ParseContent(string content, string ns, string sourceName)
    {
        var text = MaskComments(content);
        var rules = new List<YaraRule>();
        int cursor = 0;

        while (true)
        {
            var ruleStart = RuleStartRegex.Match(text, cursor);
            if (!ruleStart.Success)
            {
                break;
            }

            int openBrace = ruleStart.Index + ruleStart.Length - 1;
            int closeBrace = FindMatchingBrace(text, openBrace);
            if (closeBrace < 0)
            {
                throw new FormatException($"Unclosed rule '{ruleStart.Groups["name"].Value}' in {sourceName}.");
            }

            string name = ruleStart.Groups["name"].Value;
            string body = text[(openBrace + 1)..closeBrace];
            rules.Add(ParseRule(sourceName, ns, name, body));
            cursor = closeBrace + 1;
        }

        return rules;
    }

    public static List<YaraRule> ParseDirectory(string dir)
    {
        var result = new List<YaraRule>();
        if (!Directory.Exists(dir))
        {
            return result;
        }

        foreach (var file in Directory.EnumerateFiles(dir, "*.yar", SearchOption.AllDirectories)
                     .Concat(Directory.EnumerateFiles(dir, "*.yara", SearchOption.AllDirectories)))
        {
            result.AddRange(ParseFile(file));
        }

        return result;
    }

    private static YaraRule ParseRule(string path, string ns, string name, string body)
    {
        var conditionSection = ConditionSectionRegex.Match(body);
        if (!conditionSection.Success)
        {
            throw new FormatException($"Rule '{name}' in {path} does not contain a condition section.");
        }

        var strings = new List<YaraString>();
        var stringsSection = StringsSectionRegex.Match(body);
        if (stringsSection.Success && stringsSection.Index < conditionSection.Index)
        {
            string stringsBody = body[stringsSection.Index..conditionSection.Index];
            foreach (Match definition in StringDefinitionRegex.Matches(stringsBody))
            {
                string modifiers = definition.Groups["mods"].Value;
                var modifierNames = ModifierRegex.Matches(modifiers)
                    .Select(m => m.Value.ToLowerInvariant())
                    .ToHashSet(StringComparer.Ordinal);
                var unsupported = modifierNames
                    .Where(m => m is not "ascii" and not "wide" and not "nocase" and not "private")
                    .ToArray();
                if (unsupported.Length > 0)
                {
                    throw new NotSupportedException(
                        $"Rule '{name}' in {path} uses unsupported string modifier(s): {string.Join(", ", unsupported)}.");
                }

                bool wide = modifierNames.Contains("wide");
                strings.Add(new YaraString
                {
                    Id = definition.Groups["id"].Value,
                    Bytes = DecodeString(definition.Groups["value"].Value, path, name),
                    Ascii = modifierNames.Contains("ascii") || !wide,
                    Wide = wide,
                    Nocase = modifierNames.Contains("nocase"),
                });
            }
        }

        string rawCondition = body[(conditionSection.Index + conditionSection.Length)..].Trim();
        YaraCondition condition;
        try
        {
            condition = new ConditionParser(rawCondition).Parse();
        }
        catch (Exception ex) when (ex is FormatException or OverflowException)
        {
            throw new FormatException($"Cannot parse condition for rule '{name}' in {path}: {ex.Message}", ex);
        }

        return new YaraRule
        {
            Namespace = ns,
            Name = name,
            Strings = strings,
            Condition = condition,
            RawCondition = rawCondition,
        };
    }

    private static byte[] DecodeString(string raw, string path, string ruleName)
    {
        using var bytes = new MemoryStream(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            char c = raw[i];
            if (c != '\\')
            {
                bytes.Write(Encoding.UTF8.GetBytes(raw[i].ToString()));
                continue;
            }

            if (++i >= raw.Length)
            {
                throw new FormatException($"Unfinished string escape in rule '{ruleName}' in {path}.");
            }

            switch (raw[i])
            {
                case '\\': bytes.WriteByte((byte)'\\'); break;
                case '"': bytes.WriteByte((byte)'"'); break;
                case 'n': bytes.WriteByte((byte)'\n'); break;
                case 'r': bytes.WriteByte((byte)'\r'); break;
                case 't': bytes.WriteByte((byte)'\t'); break;
                case 'x' when i + 2 < raw.Length && IsHex(raw[i + 1]) && IsHex(raw[i + 2]):
                    bytes.WriteByte(byte.Parse(raw.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    i += 2;
                    break;
                default:
                    throw new FormatException($"Unsupported string escape '\\{raw[i]}' in rule '{ruleName}' in {path}.");
            }
        }

        return bytes.ToArray();
    }

    private static bool IsHex(char c) => (c is >= '0' and <= '9') || (c is >= 'a' and <= 'f') || (c is >= 'A' and <= 'F');

    private static int FindMatchingBrace(string text, int openBrace)
    {
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (int i = openBrace; i < text.Length; i++)
        {
            char c = text[i];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (c == '\\')
                {
                    escaped = true;
                }
                else if (c == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (c == '"')
            {
                inString = true;
            }
            else if (c == '{')
            {
                depth++;
            }
            else if (c == '}' && --depth == 0)
            {
                return i;
            }
        }

        return -1;
    }

    private static string MaskComments(string source)
    {
        var output = source.ToCharArray();
        bool inString = false;
        bool escaped = false;

        for (int i = 0; i < output.Length; i++)
        {
            if (inString)
            {
                if (escaped) escaped = false;
                else if (output[i] == '\\') escaped = true;
                else if (output[i] == '"') inString = false;
                continue;
            }

            if (output[i] == '"')
            {
                inString = true;
                continue;
            }
            if (i + 1 >= output.Length || output[i] != '/')
            {
                continue;
            }

            if (output[i + 1] == '/')
            {
                output[i++] = ' ';
                output[i] = ' ';
                while (++i < output.Length && output[i] is not '\r' and not '\n') output[i] = ' ';
                i--;
            }
            else if (output[i + 1] == '*')
            {
                output[i++] = ' ';
                output[i] = ' ';
                while (++i < output.Length)
                {
                    if (output[i] == '*' && i + 1 < output.Length && output[i + 1] == '/')
                    {
                        output[i] = output[i + 1] = ' ';
                        break;
                    }
                    if (output[i] is not '\r' and not '\n') output[i] = ' ';
                }
            }
        }

        return new string(output);
    }

    private sealed class ConditionParser
    {
        private readonly string _text;
        private Token _current;
        private int _position;

        public ConditionParser(string text)
        {
            _text = text;
            Next();
        }

        public YaraCondition Parse()
        {
            var result = ParseOr();
            if (_current.Kind != TokenKind.End)
            {
                throw Error($"Unexpected token '{_current.Text}'.");
            }
            return result;
        }

        private YaraCondition ParseOr()
        {
            var left = ParseAnd();
            while (Take(TokenKind.Or))
            {
                left = new YaraOrCondition(left, ParseAnd());
            }
            return left;
        }

        private YaraCondition ParseAnd()
        {
            var left = ParseUnary();
            while (Take(TokenKind.And))
            {
                left = new YaraAndCondition(left, ParseUnary());
            }
            return left;
        }

        private YaraCondition ParseUnary()
        {
            return Take(TokenKind.Not) ? new YaraNotCondition(ParseUnary()) : ParsePrimary();
        }

        private YaraCondition ParsePrimary()
        {
            if (Take(TokenKind.LeftParen))
            {
                var nested = ParseOr();
                Require(TokenKind.RightParen);
                return nested;
            }
            if (Take(TokenKind.True)) return new YaraBooleanCondition(true);
            if (Take(TokenKind.False)) return new YaraBooleanCondition(false);
            if (_current.Kind == TokenKind.StringReference)
            {
                string id = _current.Text;
                Next();
                return new YaraStringCondition(id);
            }
            if (_current.Kind is TokenKind.Number or TokenKind.Any or TokenKind.All or TokenKind.None)
            {
                return ParseOf();
            }
            if (Take(TokenKind.Uint16))
            {
                Require(TokenKind.LeftParen);
                long offset = ReadNumber();
                Require(TokenKind.RightParen);
                var comparison = ReadComparison();
                long value = ReadNumber();
                if (value is < ushort.MinValue or > ushort.MaxValue)
                {
                    throw Error("uint16 comparison value must fit in 16 bits.");
                }
                return new YaraUInt16Condition(offset, comparison, (ushort)value);
            }
            if (Take(TokenKind.FileSize))
            {
                return new YaraFileSizeCondition(ReadComparison(), ReadNumber());
            }

            throw Error($"Expected a condition expression, got '{_current.Text}'.");
        }

        private YaraCondition ParseOf()
        {
            YaraOfKind kind;
            int count;
            if (Take(TokenKind.Any))
            {
                kind = YaraOfKind.Any;
                count = 1;
            }
            else if (Take(TokenKind.All))
            {
                kind = YaraOfKind.All;
                count = 0;
            }
            else if (Take(TokenKind.None))
            {
                kind = YaraOfKind.None;
                count = 0;
            }
            else
            {
                kind = YaraOfKind.Count;
                long rawCount = ReadNumber();
                if (rawCount is < 0 or > int.MaxValue) throw Error("The 'of' count is out of range.");
                count = (int)rawCount;
            }

            Require(TokenKind.Of);
            IReadOnlyList<YaraStringSelector>? selectors;
            if (Take(TokenKind.Them))
            {
                selectors = null;
            }
            else
            {
                Require(TokenKind.LeftParen);
                var parsed = new List<YaraStringSelector>();
                do
                {
                    if (_current.Kind != TokenKind.StringReference)
                    {
                        throw Error("Expected a string identifier in the 'of' set.");
                    }
                    string id = _current.Text;
                    Next();
                    parsed.Add(new YaraStringSelector(id, Take(TokenKind.Star)));
                }
                while (Take(TokenKind.Comma));
                Require(TokenKind.RightParen);
                selectors = parsed;
            }

            return new YaraOfCondition(kind, count, selectors);
        }

        private long ReadNumber()
        {
            if (_current.Kind != TokenKind.Number)
            {
                throw Error($"Expected a number, got '{_current.Text}'.");
            }
            string text = _current.Text;
            Next();
            try
            {
                return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    ? checked((long)Convert.ToUInt64(text[2..], 16))
                    : long.Parse(text, CultureInfo.InvariantCulture);
            }
            catch (Exception ex) when (ex is FormatException or OverflowException)
            {
                throw Error($"Invalid number '{text}'.");
            }
        }

        private YaraComparison ReadComparison()
        {
            var comparison = _current.Kind switch
            {
                TokenKind.Equal => YaraComparison.Equal,
                TokenKind.NotEqual => YaraComparison.NotEqual,
                TokenKind.Less => YaraComparison.Less,
                TokenKind.LessOrEqual => YaraComparison.LessOrEqual,
                TokenKind.Greater => YaraComparison.Greater,
                TokenKind.GreaterOrEqual => YaraComparison.GreaterOrEqual,
                _ => throw Error($"Expected a comparison operator, got '{_current.Text}'."),
            };
            Next();
            return comparison;
        }

        private bool Take(TokenKind kind)
        {
            if (_current.Kind != kind) return false;
            Next();
            return true;
        }

        private void Require(TokenKind kind)
        {
            if (!Take(kind)) throw Error($"Expected '{kind}', got '{_current.Text}'.");
        }

        private void Next()
        {
            while (_position < _text.Length && char.IsWhiteSpace(_text[_position])) _position++;
            if (_position >= _text.Length)
            {
                _current = new Token(TokenKind.End, string.Empty);
                return;
            }

            char c = _text[_position];
            if (c == '$')
            {
                int start = ++_position;
                while (_position < _text.Length && (char.IsLetterOrDigit(_text[_position]) || _text[_position] == '_')) _position++;
                if (start == _position) throw Error("Expected an identifier after '$'.");
                _current = new Token(TokenKind.StringReference, _text[start.._position]);
                return;
            }
            if (char.IsDigit(c))
            {
                int start = _position++;
                if (c == '0' && _position < _text.Length && _text[_position] is 'x' or 'X')
                {
                    _position++;
                    while (_position < _text.Length && IsHex(_text[_position])) _position++;
                }
                else
                {
                    while (_position < _text.Length && char.IsDigit(_text[_position])) _position++;
                }
                _current = new Token(TokenKind.Number, _text[start.._position]);
                return;
            }
            if (char.IsLetter(c) || c == '_')
            {
                int start = _position++;
                while (_position < _text.Length && (char.IsLetterOrDigit(_text[_position]) || _text[_position] == '_')) _position++;
                string identifier = _text[start.._position];
                _current = new Token(identifier.ToLowerInvariant() switch
                {
                    "and" => TokenKind.And,
                    "or" => TokenKind.Or,
                    "not" => TokenKind.Not,
                    "of" => TokenKind.Of,
                    "them" => TokenKind.Them,
                    "any" => TokenKind.Any,
                    "all" => TokenKind.All,
                    "none" => TokenKind.None,
                    "true" => TokenKind.True,
                    "false" => TokenKind.False,
                    "filesize" => TokenKind.FileSize,
                    "uint16" => TokenKind.Uint16,
                    _ => TokenKind.Identifier,
                }, identifier);
                return;
            }

            _position++;
            _current = c switch
            {
                '(' => new Token(TokenKind.LeftParen, "("),
                ')' => new Token(TokenKind.RightParen, ")"),
                ',' => new Token(TokenKind.Comma, ","),
                '*' => new Token(TokenKind.Star, "*"),
                '=' when Peek('=') => new Token(TokenKind.Equal, "=="),
                '!' when Peek('=') => new Token(TokenKind.NotEqual, "!="),
                '<' when Peek('=') => new Token(TokenKind.LessOrEqual, "<="),
                '>' when Peek('=') => new Token(TokenKind.GreaterOrEqual, ">="),
                '<' => new Token(TokenKind.Less, "<"),
                '>' => new Token(TokenKind.Greater, ">"),
                _ => throw Error($"Unexpected character '{c}'."),
            };
        }

        private bool Peek(char expected)
        {
            if (_position >= _text.Length || _text[_position] != expected) return false;
            _position++;
            return true;
        }

        private FormatException Error(string message) => new($"{message} (position {_position})");

        private readonly record struct Token(TokenKind Kind, string Text);

        private enum TokenKind
        {
            End,
            Identifier,
            StringReference,
            Number,
            LeftParen,
            RightParen,
            Comma,
            Star,
            And,
            Or,
            Not,
            Of,
            Them,
            Any,
            All,
            None,
            True,
            False,
            FileSize,
            Uint16,
            Equal,
            NotEqual,
            Less,
            LessOrEqual,
            Greater,
            GreaterOrEqual,
        }
    }
}
