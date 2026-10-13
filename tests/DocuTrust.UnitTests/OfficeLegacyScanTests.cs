using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for the legacy (OLE/CFB) Office scanning path and its buffer handling.</summary>
public class OfficeLegacyScanTests
{
    private const int ChunkSize = 64 * 1024;

    // DT-001 / DT-006: the stream length (not IFormFile.Length) drove an int cast and a power-of-two allocation.
    [Theory]
    [InlineData(1_610_612_736L)] // (2^30, 2^31): old pool computed 1 << 31 and threw OverflowException
    [InlineData(3_221_225_472L)] // > int.MaxValue: (int) cast wrapped negative
    public async Task LegacyScan_StreamLengthOutsideIntRange_ReturnsVerdictWithoutOverflow(long reportedLength)
    {
        var content = TestFiles.Cfb(4096, (1000, TestFiles.Ascii("AutoOpen")));
        var file = new StreamFormFile(() => new TrickleStream(content, reportedLength: reportedLength), content.Length, "a.doc");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("AutoOpen", result.Message);
    }

    // DT-006: the size gate used IFormFile.Length while the read used the stream; actual bytes must be bounded.
    [Fact]
    public async Task LegacyScan_StreamLongerThanDeclaredLength_FailsClosed()
    {
        const int actualSize = 101 * 1024 * 1024;
        var content = TestFiles.Cfb(actualSize);
        var file = new StreamFormFile(() => new TrickleStream(content), length: 4096, "a.doc");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("size limit", result.Message);
    }

    // DT-007: a single ReadAsync may return only part of the file.
    [Fact]
    public async Task LegacyScan_ShortReads_ScansEntireFile()
    {
        var content = TestFiles.Cfb(256 * 1024, (200_000, TestFiles.Ascii("Document_Open")));
        var file = new StreamFormFile(() => new TrickleStream(content, maxChunk: 4096), content.Length, "a.doc");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("Document_Open", result.Message);
    }

    // DT-007: the 8-byte magic read was a single ReadAsync; one byte per read misrouted the file.
    [Fact]
    public async Task LegacyScan_HeaderDeliveredOneByteAtATime_IsRecognised()
    {
        var content = TestFiles.Cfb(4096, (2000, TestFiles.Ascii("AutoExec")));
        var file = new StreamFormFile(() => new TrickleStream(content, maxChunk: 1), content.Length, "a.doc");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("AutoExec", result.Message);
    }

    // DT-008: UTF-16LE was only decoded from offset 0, so odd-aligned keywords were invisible.
    [Fact]
    public async Task LegacyScan_Utf16KeywordAtOddOffset_IsDetected()
    {
        var content = TestFiles.Cfb(8192, (4097, TestFiles.Utf16("AutoOpen")));

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(content, "a.doc"));

        Assert.False(result.IsClean);
        Assert.Contains("AutoOpen", result.Message);
    }

    // DT-008: OLE directory entry names are UTF-16LE, so the ASCII-only "\x01Ole10Native" check never matched.
    [Fact]
    public async Task LegacyScan_Ole10NativeDirectoryName_IsDetected()
    {
        var content = TestFiles.Cfb(8192, (1024, TestFiles.Utf16("\u0001Ole10Native")));

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(content, "a.doc"));

        Assert.False(result.IsClean);
        Assert.Contains("embedded OLE", result.Message);
    }

    // Chunked scanning must keep an overlap so a keyword straddling a chunk boundary is still found.
    [Theory]
    [InlineData(ChunkSize - 3, false)]
    [InlineData(ChunkSize - 7, true)]
    [InlineData(2 * ChunkSize - 1, true)]
    [InlineData(3 * ChunkSize - 20, false)]
    public async Task LegacyScan_KeywordAcrossChunkBoundary_IsDetected(int offset, bool utf16)
    {
        var keyword = utf16 ? TestFiles.Utf16("Workbook_Open") : TestFiles.Ascii("Workbook_Open");
        var content = TestFiles.Cfb(4 * ChunkSize, (offset, keyword));
        var file = new StreamFormFile(() => new TrickleStream(content, maxChunk: 1000), content.Length, "a.xls");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("Workbook_Open", result.Message);
    }

    [Fact]
    public async Task LegacyScan_CleanFile_IsClean()
    {
        var content = TestFiles.Cfb(3 * ChunkSize + 123);

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(content, "a.doc"));

        Assert.True(result.IsClean, result.Message);
    }

    // DT-007 / DT-006 for the text extraction path.
    [Fact]
    public async Task LegacyTextExtraction_ShortReads_ReadsEntireFile()
    {
        var content = TestFiles.Cfb(200_000, (150_000, TestFiles.Ascii("TAILMARKER")));
        var file = new StreamFormFile(() => new TrickleStream(content, maxChunk: 4096, reportedLength: 3_221_225_472L), content.Length, "a.doc");

        var result = await new DocuTrustOfficeScanner().GetPageAsync(1, 1, file);

        Assert.Contains("TAILMARKER", result.Page);
    }
}
