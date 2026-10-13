using System.Buffers;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// A case-insensitive set of ASCII keywords searched in raw bytes, both as ASCII and as UTF-16LE.
/// UTF-16LE patterns are matched at every byte offset, so both 2-byte alignments are covered.
/// </summary>
internal sealed class KeywordSet
{
    private readonly Pattern[][] _byFirstByte;
    private readonly SearchValues<byte> _firstBytes;

    public KeywordSet(IEnumerable<string> keywords)
    {
        var buckets = new List<Pattern>[256];
        var firstBytes = new HashSet<byte>();
        int maxLength = 0;

        foreach (var keyword in keywords)
        {
            if (string.IsNullOrEmpty(keyword) || keyword.Any(c => c > 0x7F))
                throw new ArgumentException("Keywords must be non-empty ASCII strings.", nameof(keywords));

            foreach (var bytes in new[] { Encode(keyword, utf16: false), Encode(keyword, utf16: true) })
            {
                var first = bytes[0];
                (buckets[first] ??= new List<Pattern>()).Add(new Pattern(keyword, bytes));
                firstBytes.Add(first);
                if (first is >= (byte)'a' and <= (byte)'z')
                    firstBytes.Add((byte)(first & ~0x20));
                maxLength = Math.Max(maxLength, bytes.Length);
            }
        }

        if (maxLength == 0)
            throw new ArgumentException("At least one keyword is required.", nameof(keywords));

        _byFirstByte = buckets.Select(b => b?.ToArray() ?? Array.Empty<Pattern>()).ToArray();
        _firstBytes = SearchValues.Create(firstBytes.ToArray());
        MaxPatternLength = maxLength;
    }

    /// <summary>
    /// Length in bytes of the longest encoded pattern. Chunked callers must carry
    /// <c>MaxPatternLength - 1</c> bytes between chunks so boundary-spanning matches are found.
    /// </summary>
    public int MaxPatternLength { get; }

    /// <summary>
    /// Returns the first keyword whose ASCII or UTF-16LE encoding is fully contained in <paramref name="data"/>.
    /// </summary>
    public string? FindFirst(ReadOnlySpan<byte> data)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            int index = data[offset..].IndexOfAny(_firstBytes);
            if (index < 0)
                return null;

            offset += index;
            foreach (var pattern in _byFirstByte[Fold(data[offset])])
            {
                if (pattern.MatchesAt(data, offset))
                    return pattern.Keyword;
            }
            offset++;
        }
        return null;
    }

    private static byte Fold(byte value) => value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value | 0x20) : value;

    private static byte[] Encode(string keyword, bool utf16)
    {
        var bytes = new byte[utf16 ? keyword.Length * 2 : keyword.Length];
        for (int i = 0; i < keyword.Length; i++)
            bytes[utf16 ? i * 2 : i] = Fold((byte)keyword[i]);
        return bytes;
    }

    private sealed class Pattern
    {
        public Pattern(string keyword, byte[] bytes)
        {
            Keyword = keyword;
            Bytes = bytes;
        }

        public string Keyword { get; }

        public byte[] Bytes { get; }

        public bool MatchesAt(ReadOnlySpan<byte> data, int offset)
        {
            if (data.Length - offset < Bytes.Length)
                return false;

            for (int i = 0; i < Bytes.Length; i++)
            {
                if (Fold(data[offset + i]) != Bytes[i])
                    return false;
            }
            return true;
        }
    }
}
