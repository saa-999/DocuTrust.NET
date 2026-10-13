using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-021: objects with a large declared /Length must still be inspected.</summary>
public class PdfOversizedObjectTests
{
    [Fact]
    public async Task Scan_ActionStoredAsStreamWithHugeDeclaredLength_IsDetected()
    {
        var pdf = PdfFixtures.WithCatalog("/OpenAction 4 0 R",
            "<< /S /JavaScript /JS (app.alert\\(1\\)) /Length 99999999 >>\nstream\nx\nendstream");

        var result = await new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(pdf, "a.pdf"));

        Assert.False(result.IsClean);
    }
}
