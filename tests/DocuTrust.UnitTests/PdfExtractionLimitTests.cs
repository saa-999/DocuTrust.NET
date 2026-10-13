using System.Buffers;
using DocuTrust.Core.Scanning;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-026: page, glyph and text limits for PDF extraction (all fail closed).</summary>
public class PdfExtractionLimitTests
{
    private static Task<Core.Models.DocuTrustFileCheckResult> GetPage(byte[] pdf, int page, int all, PdfScanLimits limits)
        => new DocuTrustPdfScanner(ArrayPool<byte>.Shared, limits).GetPageAsync(page, all, TestFiles.FormFile(pdf, "a.pdf"));

    [Fact]
    public async Task GetPage_AllPagesBeyondPageLimit_FailsClosed()
    {
        var result = await GetPage(PdfTextExtractionTests.PdfWithText("one", "two", "three"), 0, 1, new PdfScanLimits { MaxPages = 2 });

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(0, 1)]
    public async Task GetPage_PageBeyondGlyphLimit_FailsClosed(int page, int all)
    {
        var result = await GetPage(PdfTextExtractionTests.PdfWithText("a long line of text"), page, all, new PdfScanLimits { MaxLettersPerPage = 5 });

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(0, 1)]
    public async Task GetPage_TextBeyondCharacterLimit_FailsClosed(int page, int all)
    {
        var result = await GetPage(PdfTextExtractionTests.PdfWithText("a long line of text"), page, all, new PdfScanLimits { MaxExtractedTextChars = 5 });

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task Scan_ObjectGraphBeyondLimit_FailsClosed()
    {
        var scanner = new DocuTrustPdfScanner(ArrayPool<byte>.Shared, new PdfScanLimits { MaxObjects = 1 });

        var result = await scanner.ScanFileContentAsync(TestFiles.FormFile(PdfTextExtractionTests.PdfWithText("one", "two"), "a.pdf"));

        Assert.False(result.IsClean);
        Assert.Contains("limits", result.Message);
    }

    [Fact]
    public async Task GetPage_WithinDefaultLimits_IsClean()
    {
        var result = await GetPage(PdfTextExtractionTests.PdfWithText("one", "two"), 0, 1, PdfScanLimits.Default);

        Assert.True(result.IsClean, result.Message);
    }
}
