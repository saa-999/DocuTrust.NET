using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Writer;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-025: PDF text extraction must scan first and parse once.</summary>
public class PdfTextExtractionTests
{
    internal static byte[] PdfWithText(params string[] pageTexts)
    {
        var builder = new PdfDocumentBuilder();
        var font = builder.AddStandard14Font(Standard14Font.Helvetica);
        foreach (var text in pageTexts)
            builder.AddPage(PageSize.A4).AddText(text, 12, new PdfPoint(25, 700), font);
        return builder.Build();
    }

    [Fact]
    public async Task GetPage_PdfWithJavaScript_IsNotCleanAndReturnsNoText()
    {
        var pdf = PdfFixtures.WithCatalog("/OpenAction 4 0 R", "<< /S /JavaScript /JS (app.alert\\(1\\)) >>");

        var result = await new DocuTrustPdfScanner().GetPageAsync(1, 1, TestFiles.FormFile(pdf, "a.pdf"));

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_ThreatOnlyVisibleStructurally_IsNotClean()
    {
        var pdf = PdfFixtures.BuildWithObjectStream(
            ["<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R >>", "<< /Type /Pages /Count 1 /Kids [3 0 R] >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"],
            ["<< /Type /Outlines /First 6 0 R /Count 1 >>", "<< /Title (x) /Parent 5 0 R /A << /S /Launch /F (placeholder.exe) >> >>"]);

        var result = await new DocuTrustPdfScanner().GetPageAsync(0, 1, TestFiles.FormFile(pdf, "a.pdf"));

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_CleanPdf_ReturnsTextAndIsClean()
    {
        var result = await new DocuTrustPdfScanner().GetPageAsync(1, 0, TestFiles.FormFile(PdfWithText("hello pdf"), "a.pdf"));

        Assert.True(result.IsClean, result.Message);
        Assert.Contains("hello", result.Page);
    }

    // One raw pass plus one parse: the old code opened the file three times and parsed it twice.
    [Fact]
    public async Task GetPage_OpensTheUploadAtMostTwice()
    {
        var bytes = PdfWithText("page one", "page two");
        var file = new StreamFormFile(() => new MemoryStream(bytes), bytes.Length, "a.pdf");

        var result = await new DocuTrustPdfScanner().GetPageAsync(0, 1, file);

        Assert.True(result.IsClean, result.Message);
        Assert.InRange(file.OpenCount, 1, 2);
    }
}
