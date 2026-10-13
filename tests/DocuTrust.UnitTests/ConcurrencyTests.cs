using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>
/// Regression test for DT-042: shared scanner/validator instances (e.g. registered as singletons) give every
/// concurrent caller its own correct verdict. There is no shared mutable state since the custom pool was removed.
/// </summary>
public class ConcurrencyTests
{
    [Fact]
    public async Task SharedInstances_ConcurrentMixedInputs_EachGetsCorrectVerdict()
    {
        var office = new DocuTrustOfficeScanner();
        var pdf = new DocuTrustPdfScanner();
        var validator = new DocuTrustFileScanner();

        var cleanDocx = OoxmlBuilder.Word().Build();
        var macroDocx = OoxmlBuilder.Word(macroEnabled: true).Build();
        var cleanDoc = TestFiles.Cfb(64 * 1024);
        var macroDoc = TestFiles.Cfb(64 * 1024, (40_000, TestFiles.Utf16("AutoOpen")));
        var cleanPdf = PdfTextExtractionTests.PdfWithText("concurrent");
        var jsPdf = PdfFixtures.WithCatalog("/OpenAction 4 0 R", "<< /S /JavaScript /JS (app.alert\\(1\\)) >>");

        var cases = new List<(Func<Task<bool>> Run, bool Expected)>
        {
            (async () => (await office.ScanFileContentAsync(TestFiles.FormFile(cleanDocx, "a.docx"))).IsClean, true),
            (async () => (await office.ScanFileContentAsync(TestFiles.FormFile(macroDocx, "a.docm"))).IsClean, false),
            (async () => (await office.ScanFileContentAsync(TestFiles.FormFile(cleanDoc, "a.doc"))).IsClean, true),
            (async () => (await office.ScanFileContentAsync(TestFiles.FormFile(macroDoc, "a.doc"))).IsClean, false),
            (async () => (await pdf.ScanFileContentAsync(TestFiles.FormFile(cleanPdf, "a.pdf"))).IsClean, true),
            (async () => (await pdf.ScanFileContentAsync(TestFiles.FormFile(jsPdf, "a.pdf"))).IsClean, false),
            (async () => (await validator.ValidateFileAsync(TestFiles.FormFile(cleanPdf, "a.pdf"), ".pdf")).IsValid, true),
            (async () => (await validator.ValidateFileAsync(TestFiles.FormFile(cleanPdf, "a.html"), ".pdf")).IsValid, false),
        };

        var runs = Enumerable.Range(0, 200).Select(i => cases[i % cases.Count]).ToList();
        var results = await Task.WhenAll(runs.Select(c => Task.Run(c.Run)));

        for (int i = 0; i < runs.Count; i++)
            Assert.Equal(runs[i].Expected, results[i]);
    }
}
