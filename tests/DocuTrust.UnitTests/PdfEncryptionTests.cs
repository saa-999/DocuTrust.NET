using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-019: encrypted PDFs that cannot be decrypted must not be reported clean.</summary>
public class PdfEncryptionTests
{
    // /Standard security handler with an unknown user password: the content cannot be decrypted.
    private static byte[] UndecryptablePdf()
    {
        var u = string.Concat(Enumerable.Repeat("AB", 32));
        var o = string.Concat(Enumerable.Repeat("CD", 32));
        return PdfFixtures.Build(
            [
                "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
                "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
                "<< /S /JavaScript /JS (app.alert\\(1\\)) >>",
                $"<< /Filter /Standard /V 1 /R 2 /O <{o}> /U <{u}> /P -4 >>",
            ],
            trailerExtra: "/Encrypt 5 0 R /ID [<00112233445566778899AABBCCDDEEFF><00112233445566778899AABBCCDDEEFF>]");
    }

    [Fact]
    public async Task ScanFileContentAsync_UndecryptablePdf_IsNotClean()
    {
        var result = await new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(UndecryptablePdf(), "e.pdf"));

        Assert.False(result.IsClean);
        Assert.True(result.IsEncrypted);
    }

    [Fact]
    public async Task GetPageAsync_UndecryptablePdf_IsNotClean()
    {
        var result = await new DocuTrustPdfScanner().GetPageAsync(1, 1, TestFiles.FormFile(UndecryptablePdf(), "e.pdf"));

        Assert.False(result.IsClean);
        Assert.True(result.IsEncrypted);
        Assert.Null(result.Page);
    }
}
