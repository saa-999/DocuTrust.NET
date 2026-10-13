namespace DocuTrust.Core.Scanning;

/// <summary>
/// Read-only wrapper around a decompressing stream that counts the bytes actually produced and throws
/// <see cref="ScanLimitExceededException"/> when the part limit, the shared budget or the compression ratio is exceeded.
/// Declared (attacker-controlled) sizes are never trusted.
/// </summary>
internal sealed class BoundedReadStream : Stream
{
    private readonly Stream _inner;
    private readonly long _maxBytes;
    private readonly ScanBudget _budget;
    private readonly long _compressedLength;
    private readonly int _maxRatio;
    private readonly long _ratioThreshold;

    public BoundedReadStream(Stream inner, long maxBytes, ScanBudget budget, long compressedLength, int maxRatio, long ratioThreshold)
    {
        _inner = inner;
        _maxBytes = maxBytes;
        _budget = budget;
        _compressedLength = Math.Max(1, compressedLength);
        _maxRatio = maxRatio;
        _ratioThreshold = ratioThreshold;
    }

    public long BytesRead { get; private set; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => BytesRead;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer) => Account(_inner.Read(buffer));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => Account(await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    private int Account(int read)
    {
        if (read <= 0)
            return read;

        BytesRead += read;
        if (BytesRead > _maxBytes)
            throw new ScanLimitExceededException("A package part exceeds the safety size limit.");

        _budget.Consume(read);

        // Checked in flight so a bomb is abandoned as soon as its ratio is evident.
        if (BytesRead > _ratioThreshold && BytesRead / _compressedLength > _maxRatio)
            throw new ScanLimitExceededException("A package part exceeds the maximum compression ratio (zip bomb protection).");

        return read;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _inner.Dispose();
        base.Dispose(disposing);
    }
}
