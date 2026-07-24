namespace Jrss.Core;

/// <summary>
/// Автомат Ахо-Корасик по алфавиту байт (0-255) с предвычисленной полной goto-таблицей —
/// переход между состояниями O(1), без хождения по fail-ссылкам во время поиска.
/// Тег на каждый паттерн — произвольный object (обычно (ruleIndex, stringIndex)),
/// чтобы можно было считать количество РАЗНЫХ совпавших строк на правило (threshold).
/// </summary>
public sealed class AhoCorasick<T>
{
    private const int AlphabetSize = 256;

    private sealed class TrieNode
    {
        public readonly Dictionary<byte, TrieNode> Children = new();
        public List<T>? Outputs;
        public int Id = -1;
    }

    private readonly TrieNode _root = new();
    private bool _built;

    private int[] _gotoTable = Array.Empty<int>();
    private List<T>?[] _outputs = Array.Empty<List<T>?>();
    private int _stateCount;

    public int MaxPatternLength { get; private set; }
    public int InitialState => 0;

    public void AddPattern(byte[] pattern, T tag)
    {
        if (_built)
        {
            throw new InvalidOperationException("Автомат уже построен.");
        }
        if (pattern.Length == 0)
        {
            return;
        }

        var node = _root;
        foreach (var b in pattern)
        {
            if (!node.Children.TryGetValue(b, out var next))
            {
                next = new TrieNode();
                node.Children[b] = next;
            }
            node = next;
        }
        (node.Outputs ??= new List<T>()).Add(tag);

        if (pattern.Length > MaxPatternLength)
        {
            MaxPatternLength = pattern.Length;
        }
    }

    public void Build()
    {
        if (_built) return;

        var nodes = new List<TrieNode> { _root };
        _root.Id = 0;
        var idQueue = new Queue<TrieNode>();
        idQueue.Enqueue(_root);
        while (idQueue.Count > 0)
        {
            var cur = idQueue.Dequeue();
            foreach (var child in cur.Children.Values)
            {
                child.Id = nodes.Count;
                nodes.Add(child);
                idQueue.Enqueue(child);
            }
        }

        _stateCount = nodes.Count;
        _gotoTable = new int[_stateCount * AlphabetSize];
        _outputs = new List<T>?[_stateCount];
        for (int i = 0; i < _stateCount; i++)
        {
            _outputs[i] = nodes[i].Outputs;
        }

        var fail = new int[_stateCount];
        var bfs = new Queue<int>();

        for (int c = 0; c < AlphabetSize; c++)
        {
            if (_root.Children.TryGetValue((byte)c, out var child))
            {
                int sId = child.Id;
                _gotoTable[Index(0, c)] = sId;
                fail[sId] = 0;
                bfs.Enqueue(sId);
            }
            else
            {
                _gotoTable[Index(0, c)] = 0;
            }
        }

        while (bfs.Count > 0)
        {
            int rId = bfs.Dequeue();
            var rNode = nodes[rId];
            int rFail = fail[rId];

            for (int c = 0; c < AlphabetSize; c++)
            {
                if (rNode.Children.TryGetValue((byte)c, out var sNode))
                {
                    int sId = sNode.Id;
                    int f = _gotoTable[Index(rFail, c)];
                    fail[sId] = f;
                    _gotoTable[Index(rId, c)] = sId;

                    if (_outputs[f] is not null)
                    {
                        (_outputs[sId] ??= new List<T>()).AddRange(_outputs[f]!);
                    }

                    bfs.Enqueue(sId);
                }
                else
                {
                    _gotoTable[Index(rId, c)] = _gotoTable[Index(rFail, c)];
                }
            }
        }

        _built = true;
    }

    private int Index(int state, int b) => state * AlphabetSize + b;

    /// <summary>Сканирует buffer целиком, вызывая onMatch(tag) на каждое совпадение.</summary>
    public void Scan(ReadOnlySpan<byte> buffer, Action<T> onMatch, bool asciiCaseInsensitive = false)
    {
        ScanChunk(InitialState, buffer, onMatch, asciiCaseInsensitive);
    }

    /// <summary>Потоковое сканирование с сохранением состояния между вызовами (для чтения по чанкам).</summary>
    public int ScanChunk(int state, ReadOnlySpan<byte> buffer, Action<T> onMatch, bool asciiCaseInsensitive = false)
    {
        foreach (var raw in buffer)
        {
            byte b = asciiCaseInsensitive && raw is >= (byte)'A' and <= (byte)'Z'
                ? (byte)(raw + ('a' - 'A'))
                : raw;
            state = _gotoTable[Index(state, b)];
            var outs = _outputs[state];
            if (outs is not null)
            {
                foreach (var tag in outs)
                {
                    onMatch(tag);
                }
            }
        }
        return state;
    }
}
