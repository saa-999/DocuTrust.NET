using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>
/// Regression tests for DT-023 (structural walk + raw-byte scan) and DT-024 (#xx-escaped names).
/// Payloads are benign markers (app.alert(1), placeholder paths).
/// </summary>
public class PdfDeepInspectionTests
{
    private static readonly string[] OnePage =
    [
        "<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R >>",
        "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ];

    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(byte[] pdf)
        => new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(pdf, "a.pdf"));

    // DT-023: bookmarks (outlines) were never inspected; inside an object stream the raw scan cannot see it either.
    [Fact]
    public async Task Scan_OutlineLaunchActionInObjectStream_IsDetectedStructurally()
    {
        // Objects 1-3 plain, 4 = object stream, 5-6 compressed.
        var pdf = PdfFixtures.BuildWithObjectStream(OnePage,
        [
            "<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>",
            "<< /Title (Chapter) /Parent 5 0 R /A << /S /Launch /F (placeholder.exe) >> >>",
        ]);

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
        Assert.Contains("Launch", result.Message);
        Assert.DoesNotContain("raw file content", result.Message);
    }

    [Fact]
    public async Task Scan_AnnotationPopupWithJavaScriptInObjectStream_IsDetectedStructurally()
    {
        var pdf = PdfFixtures.BuildWithObjectStream(
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [5 0 R] >>",
        ],
        [
            "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Popup 6 0 R >>",
            "<< /Type /Annot /Subtype /Popup /Rect [0 0 10 10] /A << /S /JavaScript /JS (app.alert\\(1\\)) >> >>",
        ]);

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
    }

    // DT-023: objects outside the cross-reference table (unreferenced / earlier revisions) are caught by the raw scan.
    [Fact]
    public async Task Scan_UnreferencedObjectWithEscapedJavaScript_IsDetectedByRawScan()
    {
        var pdf = PdfFixtures.Build(
            ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Count 1 /Kids [3 0 R] >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"],
            appendAfterEof: "99 0 obj\n<< /S /J#61vaScript /J#53 (app.alert\\(1\\)) >>\nendobj\n");

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
        Assert.Contains("JavaScript", result.Message);
    }

    // DT-024: PdfPig decodes #xx escapes, so the structural checks see the real name (verified, not an issue).
    [Fact]
    public async Task Scan_EscapedJavaScriptNameInObjectStream_IsDetectedStructurally()
    {
        var pdf = PdfFixtures.BuildWithObjectStream(
            ["<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>", "<< /Type /Pages /Count 1 /Kids [3 0 R] >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"],
            ["<< /S /J#61vaScript /J#53 (app.alert\\(1\\)) >>"]);

        var result = await Scan(pdf);

        Assert.False(result.IsClean);
        Assert.Contains("JavaScript", result.Message);
        Assert.DoesNotContain("raw file content", result.Message);
    }

    // No false positives: dangling references are null (ISO 32000-1 §7.3.10), names inside stream bodies are data.
    [Fact]
    public async Task Scan_DanglingReferenceAndNamesInsideStreams_AreClean()
    {
        var pdf = PdfFixtures.Build(
        [
            "<< /Type /Catalog /Pages 2 0 R /Outlines 9 0 R >>",
            "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
            "<< /Length 37 >>\nstream\n% /JS /AA /Launch endstreaX (text) Tj\nendstream",
        ]);

        var result = await Scan(pdf);

        Assert.True(result.IsClean, result.Message);
    }

    [Fact]
    public async Task Scan_CleanObjectStreamDocument_IsClean()
    {
        var pdf = PdfFixtures.BuildWithObjectStream(OnePage,
        [
            "<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>",
            "<< /Title (Chapter) /Parent 5 0 R /Dest [3 0 R /Fit] >>",
        ]);

        var result = await Scan(pdf);

        Assert.True(result.IsClean, result.Message);
    }
}
