using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for OOXML (ZIP-based) Office scanning.</summary>
public class OfficeModernScanTests
{
    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(byte[] package, string name = "upload.docx")
        => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(package, name));

    [Fact]
    public async Task ModernScan_CleanWordDocument_IsClean()
    {
        var result = await Scan(OoxmlBuilder.Word().Build());

        Assert.True(result.IsClean, result.Message);
    }

    [Fact]
    public async Task ModernScan_CleanWorkbook_IsClean()
    {
        var result = await Scan(OoxmlBuilder.Excel().Build(), "book.xlsx");

        Assert.True(result.IsClean, result.Message);
    }

    [Fact]
    public async Task ModernScan_CleanPresentation_IsClean()
    {
        var result = await Scan(OoxmlBuilder.PowerPoint().Build(), "deck.pptx");

        Assert.True(result.IsClean, result.Message);
    }

    // DT-018: passes reused one stream and reset Position, which throws on non-seekable streams.
    [Fact]
    public async Task LegacyScan_NonSeekableStream_ReturnsVerdict()
    {
        var content = TestFiles.Cfb(8192, (5000, TestFiles.Ascii("CreateObject")));
        var file = new StreamFormFile(() => new TrickleStream(content, maxChunk: 1000, seekable: false), content.Length, "a.doc");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("CreateObject", result.Message);
    }

    [Fact]
    public async Task ModernScan_NonSeekableStream_FailsClosedWithoutThrowing()
    {
        var package = OoxmlBuilder.Word().Build();
        var file = new StreamFormFile(() => new TrickleStream(package, seekable: false), package.Length, "a.docx");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task LegacyTextExtraction_NonSeekableStream_ReturnsText()
    {
        var content = TestFiles.Cfb(8192, (5000, TestFiles.Ascii("PlainWords")));
        var file = new StreamFormFile(() => new TrickleStream(content, seekable: false), content.Length, "a.doc");

        var result = await new DocuTrustOfficeScanner().GetPageAsync(1, 1, file);

        Assert.Contains("PlainWords", result.Page);
    }
}
