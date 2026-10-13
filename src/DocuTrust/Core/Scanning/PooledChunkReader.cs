using System.Buffers;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// Streams data through one bounded buffer rented from an <see cref="ArrayPool{T}"/>.
/// Each window handed to the callback is the carried-over tail of the previous window followed by new data,
/// so patterns up to <c>overlap + 1</c> bytes long that straddle a chunk boundary are still seen whole.
/// </summary>
internal static class PooledChunkReader
{
    /// <summary>Bytes of new data read per window.</summary>
    internal const int ChunkSize = 64 * 1024;

    /// <summary>Inspects one window. Return <c>true</c> to stop reading.</summary>
    internal delegate bool WindowHandler(ReadOnlySpan<byte> window, long windowOffset);

    internal static async Task<ChunkReadResult> ReadAsync(
        Stream stream,
        ArrayPool<byte> pool,
        int overlap,
        long maxBytes,
        WindowHandler handler,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(handler);
        if (overlap < 0 || overlap > ChunkSize)
            throw new ArgumentOutOfRangeException(nameof(overlap));

        // The pool may hand back a larger array; only the first `capacity` bytes are ever used.
        int capacity = ChunkSize + overlap;
        byte[] buffer = pool.Rent(capacity);
        try
        {
            int carried = 0;
            long windowOffset = 0;
            long total = 0;

            while (true)
            {
                token.ThrowIfCancellationRequested();

                int filled = carried;
                bool endOfStream = false;
                while (filled < capacity)
                {
                    // ReadAsync may return fewer bytes than requested: keep reading until the window is full.
                    int read = await stream.ReadAsync(buffer.AsMemory(filled, capacity - filled), token).ConfigureAwait(false);
                    if (read == 0)
                    {
                        endOfStream = true;
                        break;
                    }

                    filled += read;
                    total += read;
                    if (total > maxBytes)
                        return new ChunkReadResult(total, LimitExceeded: true, Stopped: false);
                }

                if (filled > carried && handler(buffer.AsSpan(0, filled), windowOffset))
                    return new ChunkReadResult(total, LimitExceeded: false, Stopped: true);

                if (endOfStream)
                    return new ChunkReadResult(total, LimitExceeded: false, Stopped: false);

                int keep = Math.Min(overlap, filled);
                buffer.AsSpan(filled - keep, keep).CopyTo(buffer);
                windowOffset += filled - keep;
                carried = keep;
            }
        }
        finally
        {
            // The buffer held user file contents: clear it before it goes back to the shared pool.
            pool.Return(buffer, clearArray: true);
        }
    }
}

/// <summary>Outcome of <see cref="PooledChunkReader.ReadAsync"/>.</summary>
internal readonly record struct ChunkReadResult(long BytesRead, bool LimitExceeded, bool Stopped);
