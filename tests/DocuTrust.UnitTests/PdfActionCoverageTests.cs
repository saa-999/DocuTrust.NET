using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-022: action types, annotation subtypes, form-field triggers and URI schemes.</summary>
public class PdfActionCoverageTests
{
    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(byte[] pdf)
        => new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(pdf, "a.pdf"));

    private static byte[] LinkWithAction(string action)
        => PdfFixtures.WithPage("/Annots [4 0 R]", $"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A {action} >>");

    [Theory]
    [InlineData("javascript:app.alert\\(1\\)")]
    [InlineData("JavaScript:app.alert\\(1\\)")]
    [InlineData("file:///C:/placeholder.exe")]
    [InlineData("\\\\\\\\placeholder-host\\\\share")]
    [InlineData("smb://placeholder-host/share")]
    [InlineData("C:\\\\placeholder.exe")]
    public async Task Scan_UriActionWithDangerousTarget_IsDetected(string uri)
    {
        var result = await Scan(LinkWithAction($"<< /S /URI /URI ({uri}) >>"));

        Assert.False(result.IsClean);
    }

    [Theory]
    [InlineData("SubmitForm")]
    [InlineData("GoToE")]
    [InlineData("Rendition")]
    [InlineData("RichMediaExecute")]
    [InlineData("Sound")]
    [InlineData("Movie")]
    [InlineData("javascript")]
    [InlineData("LAUNCH")]
    public async Task Scan_DangerousOpenActionType_IsDetected(string type)
    {
        var result = await Scan(PdfFixtures.WithCatalog("/OpenAction 4 0 R", $"<< /S /{type} /F (placeholder) >>"));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task Scan_JsKeyWithoutActionType_IsDetected()
    {
        var result = await Scan(PdfFixtures.WithCatalog("/OpenAction 4 0 R", "<< /JS (app.alert\\(1\\)) >>"));

        Assert.False(result.IsClean);
        Assert.Contains("JavaScript", result.Message);
    }

    [Theory]
    [InlineData("RichMedia")]
    [InlineData("Screen")]
    [InlineData("Movie")]
    [InlineData("Sound")]
    [InlineData("3D")]
    public async Task Scan_ActiveAnnotationSubtype_IsDetected(string subtype)
    {
        var pdf = PdfFixtures.WithPage("/Annots [4 0 R]", $"<< /Type /Annot /Subtype /{subtype} /Rect [0 0 10 10] >>");

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
        Assert.Contains(subtype, result.Message);
    }

    [Fact]
    public async Task Scan_FormFieldAdditionalActionWithoutWidget_IsDetected()
    {
        var pdf = PdfFixtures.WithCatalog("/AcroForm << /Fields [4 0 R] >>",
            "<< /FT /Tx /T (field) /AA << /K << /S /JavaScript /JS (app.alert\\(1\\)) >> >> >>");

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task Scan_FormFieldKidWithJavaScriptAction_IsDetected()
    {
        var pdf = PdfFixtures.WithCatalog("/AcroForm << /Fields [4 0 R] >>",
            "<< /T (parent) /Kids [5 0 R] >>",
            "<< /T (child) /Parent 4 0 R /A << /S /JavaScript /JS (app.alert\\(1\\)) >> >>");

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
    }

    // No false positives for ordinary links, mailto links and plain form fields.
    [Fact]
    public async Task Scan_OrdinaryLinksAndFields_AreClean()
    {
        var pdf = PdfFixtures.Build(
        [
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>",
            "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R 5 0 R] >>",
            "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (https://example.com/a:b) >> >>",
            "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (mailto:someone@example.com) >> >>",
            "<< /FT /Tx /T (name) /V (value) >>",
        ]);

        var result = await Scan(pdf);

        Assert.True(result.IsClean, result.Message);
    }
}
