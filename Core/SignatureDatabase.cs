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
        return LoadFromStream(File.OpenRead(path));
    }

    public static SignatureDatabase LoadFromStream(Stream stream)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
        };
        options.Converters.Add(new JsonStringEnumConverter());

        using var reader = new StreamReader(stream);
        var families = JsonSerializer.Deserialize<List<SignatureFamily>>(reader.ReadToEnd(), options)
            ?? throw new InvalidDataException("signatures.json does not contain a families array.");
        if (families.Count == 0)
        {
            throw new InvalidDataException("signatures.json is empty — nothing to scan.");
        }

        var automaton = new AhoCorasick<DetectionTag>();
        var seen = new HashSet<(string Family, string Pattern, bool Wide)>();
        int patternCount = 0;

        foreach (var family in families)
        {
            if (string.IsNullOrWhiteSpace(family.Family))
            {
                throw new InvalidDataException("Signature database contains a family without a name.");
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
