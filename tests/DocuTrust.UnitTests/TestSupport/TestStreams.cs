using System.Buffers;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace DocuTrust.Tests.TestSupport;

internal static class TestFiles
{
    public static IFormFile FormFile(byte[] content, string fileName = "upload.bin")
        => new FormFile(new MemoryStream(content), 0, content.Length, "file", fileName);

    public static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);

    public static byte[] Utf16(string value) => Encoding.Unicode.GetBytes(value);

    /// <summary>
    /// Builds a buffer that starts with the OLE/CFB magic, is padded with a benign filler and has
    /// <paramref name="payloads"/> written at the given offsets.
    /// </summary>
    public static byte[] Cfb(int size, params (int Offset, byte[] Data)[] payloads)
    {
        var bytes = new byte[size];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = (byte)('.' + (i % 7));
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        foreach (var (offset, data) in payloads)
            data.CopyTo(bytes, offset);
        return bytes;
    }
}

/// <summary>An <see cref="IFormFile"/> whose stream and declared length are fully controlled by the test.</summary>
internal sealed class StreamFormFile : IFormFile
{
    private readonly Func<Stream> _open;

    public StreamFormFile(Func<Stream> open, long length, string fileName = "upload.bin")
    {
        _open = open;
        Length = length;
        FileName = fileName;
    }

    public string ContentType => "application/octet-stream";
    public string ContentDisposition => $"form-data; name=\"file\"; filename=\"{FileName}\"";
    public IHeaderDictionary Headers { get; } = new HeaderDictionary();
    public long Length { get; }
    public string Name => "file";
    public string FileName { get; }
    public int OpenCount { get; private set; }

    public Stream OpenReadStream()
    {
        OpenCount++;
        return _open();
    }

    public void CopyTo(Stream target) => OpenReadStream().CopyTo(target);

    public Task CopyToAsync(Stream target, CancellationToken cancellationToken = default)
        => OpenReadStream().CopyToAsync(target, cancellationToken);
}

/// <summary>
/// A read-only stream that returns at most <c>maxChunk</c> bytes per read (like a network stream),
/// optionally reports a fake <see cref="Length"/>, and can be made non-seekable.
/// </summary>
internal sealed class TrickleStream : Stream
{
    private readonly byte[] _data;
    private readonly int _maxChunk;
    private readonly long? _reportedLength;
    private readonly bool _seekable;
    private int _position;

    public TrickleStream(byte[] data, int maxChunk = int.MaxValue, long? reportedLength = null, bool seekable = true)
    {
        _data = data;
        _maxChunk = maxChunk;
        _reportedLength = reportedLength;
        _seekable = seekable;
    }

    public override bool CanRead => true;
    public override bool CanSeek => _seekable;
    public override bool CanWrite => false;
    public override long Length => _seekable ? _reportedLength ?? _data.Length : throw new NotSupportedException();

    public override long Position
    {
        get => _seekable ? _position : throw new NotSupportedException();
        set
        {
            if (!_seekable) throw new NotSupportedException();
            _position = (int)Math.Clamp(value, 0, _data.Length);
        }
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int n = Math.Min(Math.Min(buffer.Length, _maxChunk), _data.Length - _position);
        _data.AsSpan(_position, n).CopyTo(buffer);
        _position += n;
        return n;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Read(buffer.Span));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => Task.FromResult(Read(buffer, offset, count));

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (!_seekable) throw new NotSupportedException();
        Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            _ => _data.Length + offset
        };
        return _position;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>An <see cref="ArrayPool{T}"/> that records every rent and return.</summary>
internal sealed class RecordingArrayPool : ArrayPool<byte>
{
    private readonly object _gate = new();
    private readonly HashSet<byte[]> _outstanding = new(ReferenceEqualityComparer.Instance);

    public int Rents { get; private set; }
    public int Returns { get; private set; }
    public int UnclearedReturns { get; private set; }
    public int MaxRequested { get; private set; }
    public int ForeignReturns { get; private set; }

    public override byte[] Rent(int minimumLength)
    {
        lock (_gate)
        {
            Rents++;
            MaxRequested = Math.Max(MaxRequested, minimumLength);
            // Deliberately larger than requested: callers must not assume an exact length.
            var array = new byte[minimumLength + 17];
            _outstanding.Add(array);
            return array;
        }
    }

    public override void Return(byte[] array, bool clearArray = false)
    {
        lock (_gate)
        {
            Returns++;
            if (!clearArray) UnclearedReturns++;
            if (!_outstanding.Remove(array)) ForeignReturns++;
        }
    }

    public int Outstanding
    {
        get { lock (_gate) return _outstanding.Count; }
    }
}
