using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-020 (action chains: depth limit, /Next arrays, cycles).</summary>
public class PdfActionChainTests
{
    private const string Js = "<< /S /JavaScript /JS (app.alert\\(1\\)) >>";

    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(byte[] pdf)
        => new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(pdf, "a.pdf"));

    [Fact]
    public async Task Scan_JavaScriptInNextArray_IsDetected()
    {
        var pdf = PdfFixtures.WithCatalog("/OpenAction 4 0 R",
            "<< /S /GoTo /D [3 0 R /Fit] /Next [5 0 R] >>",
            Js);

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task Scan_JavaScriptBeyondDepthLimit_FailsClosed()
    {
        // 17 GoTo actions (objects 4..20) chained through /Next, then JavaScript (object 21).
        var actions = Enumerable.Range(0, 17).Select(i => $"<< /S /GoTo /D [3 0 R /Fit] /Next {i + 5} 0 R >>").ToList();
        actions.Add(Js);

        var result = await Scan(PdfFixtures.WithCatalog("/OpenAction 4 0 R", [.. actions]));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task Scan_CyclicActionChain_FailsClosedAndTerminates()
    {
        var pdf = PdfFixtures.WithCatalog("/OpenAction 4 0 R",
            "<< /S /GoTo /D [3 0 R /Fit] /Next 5 0 R >>",
            "<< /S /GoTo /D [3 0 R /Fit] /Next 4 0 R >>");

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task Scan_ShortBenignActionChain_IsClean()
    {
        var pdf = PdfFixtures.WithCatalog("/OpenAction 4 0 R",
            "<< /S /GoTo /D [3 0 R /Fit] /Next [5 0 R] >>",
            "<< /S /GoTo /D [3 0 R /FitH 100] >>");

        var result = await Scan(pdf);

        Assert.True(result.IsClean, result.Message);
    }
}
