using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jrss.Core;

/// <summary>Compiles the Rust signature database into an Aho-Corasick automaton.</summary>
public sealed class SignatureDatabase
{
    public AhoCorasick<DetectionTag> Automaton { get; }
    public int FamilyCount { get; }
    public int PatternCount { get; }

    private SignatureDatabase(AhoCorasick<DetectionTag> automaton, int familyCount, int patternCount)
    {
        Automaton = automaton;
        FamilyCount = familyCount;
        PatternCount = patternCount;
    }

    public static SignatureDatabase LoadFromFile(string path)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
        };
        options.Converters.Add(new JsonStringEnumConverter());

        var families = JsonSerializer.Deserialize<List<SignatureFamily>>(File.ReadAllText(path), options)
            ?? throw new InvalidDataException("data/signatures.json не содержит массива семейств.");
        if (families.Count == 0)
        {
            throw new InvalidDataException("data/signatures.json пуст — сканировать нечего.");
        }

        var automaton = new AhoCorasick<DetectionTag>();
        var seen = new HashSet<(string Family, string Pattern, bool Wide)>();
        int patternCount = 0;

        foreach (var family in families)
        {
            if (string.IsNullOrWhiteSpace(family.Family))
            {
                throw new InvalidDataException("В базе сигнатур найдено семейство без имени.");
            }

            foreach (var pattern in family.Patterns)
            {
                if (string.IsNullOrEmpty(pattern))
                {
                    continue;
                }

                patternCount++;
                var tag = new DetectionTag(family.Family, family.Severity);
                if (seen.Add((family.Family, pattern, false)))
                {
                    automaton.AddPattern(Encoding.UTF8.GetBytes(pattern), tag);
                }
                if (seen.Add((family.Family, pattern, true)))
                {
                    automaton.AddPattern(Encoding.Unicode.GetBytes(pattern), tag);
                }
            }
        }

        automaton.Build();
        return new SignatureDatabase(automaton, families.Count, patternCount);
    }
}
