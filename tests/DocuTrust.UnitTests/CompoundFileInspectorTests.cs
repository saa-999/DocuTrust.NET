using DocuTrust.Core.Scanning;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>DT-015 follow-up: the CFB reader inspects only stream prefixes and never materialises whole streams.</summary>
public class CompoundFileInspectorTests
{
    [Fact]
    public void Inspect_LargeWordStream_ReadsOnlyThePrefix()
    {
        var fib = new byte[8 * 1024 * 1024];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(fib, 0xA5EC);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(fib.AsSpan(10), 0x0100);
        var cfb = new CfbBuilder().Stream("WordDocument", fib).Build();
        using var stream = new CountingStream(cfb);

        var verdict = CompoundFileInspector.Inspect(stream);

        Assert.Equal(CompoundFileVerdict.Encrypted, verdict);
        // Header, FAT and directory plus one data sector; the old code read the whole 8 MB chain.
        Assert.True(stream.BytesRead < 1024 * 1024, $"read {stream.BytesRead} bytes");
    }

    [Fact]
    public void Inspect_GarbageAfterMagic_IsUnreadableNotEncrypted()
    {
        Assert.Equal(CompoundFileVerdict.Unreadable, CompoundFileInspector.Inspect(new MemoryStream(TestFiles.Cfb(8192))));
    }

    private sealed class CountingStream : MemoryStream
    {
        public CountingStream(byte[] data) : base(data, writable: false) { }

        public long BytesRead { get; private set; }

        // Only the array overload is overridden: for derived types MemoryStream.Read(Span) is routed through
        // Stream.Read(Span) to this method, so overriding both would recurse.
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = base.Read(buffer, offset, count);
            BytesRead += n;
            return n;
        }
    }
}
