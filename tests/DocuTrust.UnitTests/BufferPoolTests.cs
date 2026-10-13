using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for the replacement of the custom memory pool (DT-001..DT-005).</summary>
public class BufferPoolTests
{
    private const int MaxBufferBytes = 80 * 1024;

    // DT-002 / DT-005: the hand-written pool (unchecked Return, racy counters) must not come back.
    [Fact]
    public void Assembly_HasNoCustomMemoryPool()
    {
        var names = typeof(DocuTrustOfficeScanner).Assembly.GetTypes().Select(t => t.Name).ToList();

        Assert.DoesNotContain(names, n => n.StartsWith("DoucTrustMemoryPool", StringComparison.Ordinal));
        Assert.DoesNotContain(names, n => n.StartsWith("IMemoryPool", StringComparison.Ordinal));
    }

    // DT-003 / DT-004: buffers are bounded, returned exactly once, and cleared because they hold file bytes.
    [Fact]
    public async Task LegacyScan_RentsBoundedBuffers_ReturnsEachOnceCleared()
    {
        var pool = new RecordingArrayPool();
        var content = TestFiles.Cfb(5 * 1024 * 1024, (4 * 1024 * 1024, TestFiles.Ascii("AutoOpen")));

        var result = await new DocuTrustOfficeScanner(pool).ScanFileContentAsync(TestFiles.FormFile(content, "a.doc"));

        Assert.False(result.IsClean);
        AssertPoolHygiene(pool);
    }

    [Fact]
    public async Task LegacyTextExtraction_RentsBoundedBuffers_ReturnsEachOnceCleared()
    {
        var pool = new RecordingArrayPool();
        var content = TestFiles.Cfb(3 * 1024 * 1024);

        await new DocuTrustOfficeScanner(pool).GetPageAsync(1, 1, TestFiles.FormFile(content, "a.doc"));

        AssertPoolHygiene(pool);
    }

    [Fact]
    public async Task LegacyScan_WhenStreamThrows_StillReturnsBufferCleared()
    {
        var pool = new RecordingArrayPool();
        var content = TestFiles.Cfb(4096);
        var file = new StreamFormFile(() => new ThrowAfterHeaderStream(content), content.Length, "a.doc");

        await Assert.ThrowsAnyAsync<Exception>(() => new DocuTrustOfficeScanner(pool).ScanFileContentAsync(file));

        AssertPoolHygiene(pool);
    }

    private static void AssertPoolHygiene(RecordingArrayPool pool)
    {
        Assert.True(pool.Rents > 0, "expected the scanner to rent from the pool");
        Assert.Equal(pool.Rents, pool.Returns);
        Assert.Equal(0, pool.Outstanding);
        Assert.Equal(0, pool.ForeignReturns);
        Assert.Equal(0, pool.UnclearedReturns);
        Assert.InRange(pool.MaxRequested, 1, MaxBufferBytes);
    }

    private sealed class ThrowAfterHeaderStream : MemoryStream
    {
        public ThrowAfterHeaderStream(byte[] data) : base(data) { }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => Position >= 8 && buffer.Length > 8 ? throw new IOException("boom") : base.ReadAsync(buffer, cancellationToken);
    }
}
