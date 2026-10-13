using System.IO.Compression;
using System.Text;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-027 (PDF/ZIP polyglots).</summary>
public class PdfPolyglotTests
{
    private static readonly string[] OnePage =
    [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ];

    private static string BenignZip()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var entry = zip.CreateEntry("readme.txt", CompressionLevel.NoCompression).Open();
            entry.Write("benign text"u8);
        }
        return Encoding.Latin1.GetString(ms.ToArray());
    }

    [Fact]
    public async Task Scan_ZipAppendedAfterEof_IsDetected()
    {
        var pdf = PdfFixtures.Build(OnePage, appendAfterEof: BenignZip());

        var result = await new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(pdf, "a.pdf"));

        Assert.False(result.IsClean);
        Assert.Contains("polyglot", result.Message);
    }

    // ZIP-like bytes inside a stream body are ordinary (possibly compressed) data, not a polyglot.
    [Fact]
    public async Task Scan_ZipSignatureInsideStreamBody_IsClean()
    {
        var data = "PK\u0003\u0004 PK\u0005\u0006";
        var pdf = PdfFixtures.Build(
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
            $"<< /Length {data.Length} >>\nstream\n{data}\nendstream",
        ]);

        var result = await new DocuTrustPdfScanner().ScanFileContentAsync(TestFiles.FormFile(pdf, "a.pdf"));

        Assert.True(result.IsClean, result.Message);
    }
}
