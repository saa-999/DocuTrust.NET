namespace DocuTrust.Core.Scanning;

/// <summary>
/// Defense in depth for PDFs: a byte-level tokenizer that looks for dangerous PDF names anywhere outside stream
/// bodies, including unreferenced objects and earlier incremental-update revisions that a parser never surfaces.
/// Names are decoded (<c>/J#61vaScript</c> → <c>JavaScript</c>) and compared case-insensitively. Stream bodies
/// (between <c>stream</c> and <c>endstream</c>) are skipped because compressed or binary data would produce
/// false positives; objects inside object streams are covered by the structural walk instead.
/// Feed the file in order with <see cref="Feed"/> and call <see cref="Complete"/> at the end.
/// </summary>
internal sealed class PdfRawScanner
{
    private const int MaxNameLength = 64;

    private static readonly Dictionary<string, string> DangerousNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["JavaScript"] = "Embedded JavaScript (/JavaScript) found in raw file content.",
        ["JS"] = "Embedded JavaScript (/JS) found in raw file content.",
        ["Launch"] = "Suspicious PDF construct /Launch found in raw file content.",
        ["EmbeddedFile"] = "Suspicious PDF construct /EmbeddedFile found in raw file content.",
        ["EmbeddedFiles"] = "Suspicious PDF construct /EmbeddedFiles found in raw file content.",
        ["EF"] = "Suspicious PDF construct /EF found in raw file content.",
        ["FileAttachment"] = "Suspicious PDF construct /FileAttachment found in raw file content.",
        ["RichMedia"] = "Suspicious PDF construct /RichMedia found in raw file content.",
        ["RichMediaExecute"] = "Suspicious PDF construct /RichMediaExecute found in raw file content.",
        ["RichMediaContent"] = "Suspicious PDF construct /RichMediaContent found in raw file content.",
        ["XFA"] = "Suspicious PDF construct /XFA found in raw file content.",
        ["AA"] = "Suspicious PDF construct /AA found in raw file content.",
        ["ImportData"] = "Suspicious PDF construct /ImportData found in raw file content.",
        ["GoToE"] = "Suspicious PDF construct /GoToE found in raw file content.",
        ["GoToR"] = "Suspicious PDF construct /GoToR found in raw file content.",
        ["SubmitForm"] = "Suspicious PDF construct /SubmitForm found in raw file content.",
        ["Rendition"] = "Suspicious PDF construct /Rendition found in raw file content.",
        ["Sound"] = "Suspicious PDF construct /Sound found in raw file content.",
        ["Movie"] = "Suspicious PDF construct /Movie found in raw file content.",
        ["Screen"] = "Suspicious PDF construct /Screen found in raw file content.",
        ["3D"] = "Suspicious PDF construct /3D found in raw file content.",
    };

    private static readonly byte[] EndStream = "endstream"u8.ToArray();
    private static readonly int[] EndStreamFailure = BuildFailureTable(EndStream);

    private readonly char[] _name = new char[MaxNameLength];
    private readonly byte[] _word = new byte[8];
    private State _state = State.Normal;
    private int _nameLength;
    private bool _nameOverflow;
    private int _hexHigh;
    private int _wordLength;
    private int _endStreamMatched;

    /// <summary>The first threat found, or null. Scanning continues after a threat so the whole file is read.</summary>
    public string? Threat { get; private set; }

    /// <summary>True when an <c>/Encrypt</c> entry was seen (reported with a raw threat).</summary>
    public bool SawEncrypt { get; private set; }

    private enum State
    {
        Normal,
        Name,
        NameHexHigh,
        NameHexLow,
        Stream,
    }

    public void Feed(ReadOnlySpan<byte> data)
    {
        foreach (byte b in data)
            Step(b);
    }

    public void Complete()
    {
        if (_state is State.Name or State.NameHexHigh or State.NameHexLow)
            EndName();
        _state = State.Normal;
    }

    private void Step(byte b)
    {
        while (true)
        {
            switch (_state)
            {
                case State.Stream:
                    AdvanceEndStream(b);
                    return;

                case State.NameHexHigh:
                    if (HexValue(b) is int high)
                    {
                        _hexHigh = high;
                        _state = State.NameHexLow;
                        return;
                    }
                    Append('#');
                    _state = State.Name;
                    continue; // reprocess b as a name character

                case State.NameHexLow:
                    if (HexValue(b) is int low)
                    {
                        Append((char)(_hexHigh * 16 + low));
                        _state = State.Name;
                        return;
                    }
                    Append('#');
                    Append(HexDigit(_hexHigh));
                    _state = State.Name;
                    continue;

                case State.Name:
                    if (b == '#')
                    {
                        _state = State.NameHexHigh;
                        return;
                    }
                    if (IsRegular(b))
                    {
                        Append((char)b);
                        return;
                    }
                    EndName();
                    _state = State.Normal;
                    continue; // the delimiter itself still matters (e.g. "/AA/JS")

                default:
                    if (IsRegular(b))
                    {
                        if (_wordLength < _word.Length)
                            _word[_wordLength] = b;
                        _wordLength++;
                        return;
                    }

                    // "stream" followed by an end-of-line starts a stream body (ISO 32000-1 §7.3.8.1).
                    bool streamKeyword = _wordLength == 6 && _word.AsSpan(0, 6).SequenceEqual("stream"u8);
                    _wordLength = 0;
                    if (streamKeyword && (b == '\r' || b == '\n'))
                    {
                        _state = State.Stream;
                        _endStreamMatched = 0;
                        return;
                    }

                    if (b == '/')
                    {
                        _state = State.Name;
                        _nameLength = 0;
                        _nameOverflow = false;
                    }
                    return;
            }
        }
    }

    private void Append(char c)
    {
        if (_nameLength < MaxNameLength)
            _name[_nameLength++] = c;
        else
            _nameOverflow = true;
    }

    private void EndName()
    {
        if (_nameOverflow || _nameLength == 0)
            return;

        var name = new string(_name, 0, _nameLength);
        if (name.Equals("Encrypt", StringComparison.OrdinalIgnoreCase))
            SawEncrypt = true;
        else if (Threat == null && DangerousNames.TryGetValue(name, out var threat))
            Threat = threat;
    }

    private void AdvanceEndStream(byte b)
    {
        // Knuth-Morris-Pratt match of "endstream" so overlapping prefixes are not missed.
        while (_endStreamMatched > 0 && EndStream[_endStreamMatched] != b)
            _endStreamMatched = EndStreamFailure[_endStreamMatched - 1];
        if (EndStream[_endStreamMatched] == b)
            _endStreamMatched++;
        if (_endStreamMatched == EndStream.Length)
        {
            _state = State.Normal;
            _endStreamMatched = 0;
            _wordLength = 0;
        }
    }

    private static int[] BuildFailureTable(byte[] pattern)
    {
        var failure = new int[pattern.Length];
        for (int i = 1, k = 0; i < pattern.Length; i++)
        {
            while (k > 0 && pattern[i] != pattern[k])
                k = failure[k - 1];
            if (pattern[i] == pattern[k])
                k++;
            failure[i] = k;
        }
        return failure;
    }

    // ISO 32000-1 §7.2.2: white-space and delimiter characters; everything else is "regular".
    private static bool IsRegular(byte b) => b switch
    {
        0x00 or 0x09 or 0x0A or 0x0C or 0x0D or 0x20 => false,
        (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%' => false,
        _ => true,
    };

    private static int? HexValue(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => null,
    };

    private static char HexDigit(int value) => (char)(value < 10 ? '0' + value : 'A' + value - 10);
}
