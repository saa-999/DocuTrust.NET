using System.Buffers;
using DocuTrust.Core.Scanning;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-039: scans run under a wall-clock budget that fails closed.</summary>
public class ScanTimeoutTests
{
    private static readonly byte[] Docx = OoxmlBuilder.Word().Build();
    private static readonly byte[] Pdf = PdfTextExtractionTests.PdfWithText("timeout");

    [Fact]
    public async Task OfficeScan_BudgetExpired_FailsClosed()
    {
        var scanner = new DocuTrustOfficeScanner(ArrayPool<byte>.Shared, new OfficeScanLimits { ScanTimeout = TimeSpan.Zero });

        var scan = await scanner.ScanFileContentAsync(TestFiles.FormFile(Docx, "a.docx"));
        var page = await scanner.GetPageAsync(1, 1, TestFiles.FormFile(Docx, "a.docx"));

        Assert.False(scan.IsClean);
        Assert.False(scan.IsScanned);
        Assert.Contains("time limit", scan.Message);
        Assert.False(page.IsClean);
        Assert.Null(page.Page);
    }

    [Fact]
    public async Task PdfScan_BudgetExpired_FailsClosed()
    {
        var scanner = new DocuTrustPdfScanner(ArrayPool<byte>.Shared, new PdfScanLimits { ScanTimeout = TimeSpan.Zero });

        var scan = await scanner.ScanFileContentAsync(TestFiles.FormFile(Pdf, "a.pdf"));
        var page = await scanner.GetPageAsync(0, 1, TestFiles.FormFile(Pdf, "a.pdf"));

        Assert.False(scan.IsClean);
        Assert.Contains("time limit", scan.Message);
        Assert.False(page.IsClean);
        Assert.Null(page.Page);
    }

    [Fact]
    public async Task SlowUpload_ExceedingBudget_FailsClosedInsteadOfHanging()
    {
        // 256 KB delivered 1 KB per 50 ms would take ~13 s; the budget is 300 ms.
        var content = TestFiles.Cfb(256 * 1024);
        var file = new StreamFormFile(() => new SlowStream(content, TimeSpan.FromMilliseconds(50), 1024), content.Length, "a.doc");
        var scanner = new DocuTrustOfficeScanner(ArrayPool<byte>.Shared, new OfficeScanLimits { ScanTimeout = TimeSpan.FromMilliseconds(300) });

        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await scanner.ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("time limit", result.Message);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"took {watch.Elapsed}");
    }

    // The caller's own cancellation is still reported as cancellation, not as a verdict.
    [Fact]
    public async Task Scans_CallerCancellation_StillThrows()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(Docx, "a.docx"), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(Pdf, "a.pdf"), cts.Token));
    }

    [Fact]
    public async Task Scans_WithinDefaultBudget_Complete()
    {
        Assert.True((await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(Docx, "a.docx"))).IsClean);
        Assert.True((await new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(Pdf, "a.pdf"))).IsClean);
    }
}
