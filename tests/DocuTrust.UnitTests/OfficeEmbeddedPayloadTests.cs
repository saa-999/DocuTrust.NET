using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-011 (embedded payload detection). All payloads are benign stand-ins.</summary>
public class OfficeEmbeddedPayloadTests
{
    private static readonly byte[] PeLikeHeader = TestFiles.Ascii("MZ-benign stand-in for a PE header");

    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(OoxmlBuilder builder, string name = "upload.docx")
        => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(builder.Build(), name));

    [Fact]
    public async Task ModernScan_ExecutableInCapitalisedEmbeddingsFolder_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word().Part("word/Embeddings/setup.exe", TestFiles.Ascii("plain bytes")));

        Assert.False(result.IsClean);
        Assert.Contains("executable", result.Message);
    }

    [Fact]
    public async Task ModernScan_DangerousExtensionOutsideEmbeddings_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word().Part("word/media/run.hta", "<html>benign</html>"));

        Assert.False(result.IsClean);
        Assert.Contains("executable", result.Message);
    }

    [Theory]
    [InlineData(".hta")]
    [InlineData(".lnk")]
    [InlineData(".cmd")]
    [InlineData(".msi")]
    [InlineData(".dll")]
    [InlineData(".cpl")]
    [InlineData(".pif")]
    [InlineData(".reg")]
    [InlineData(".iso")]
    [InlineData(".scf")]
    [InlineData(".xll")]
    [InlineData(".docm")]
    [InlineData(".EXE.")]
    public async Task ModernScan_ExtendedBlockList_IsDetected(string extension)
    {
        var result = await Scan(OoxmlBuilder.Word().Part($"word/embeddings/object{extension}", TestFiles.Ascii("plain bytes")));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task ModernScan_PeHeaderBehindInnocentName_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/data.dat", PeLikeHeader));

        Assert.False(result.IsClean);
        Assert.Contains("executable", result.Message);
    }

    [Fact]
    public async Task ModernScan_ElfHeaderBehindInnocentName_IsDetected()
    {
        var elf = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00 };

        var result = await Scan(OoxmlBuilder.Word().Part("word/media/image9.png", elf));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task ModernScan_OlePackageObject_IsDetected()
    {
        var ole = TestFiles.Cfb(4096, (1024, TestFiles.Utf16("\u0001Ole10Native")));

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/oleObject1.bin", ole));

        Assert.False(result.IsClean);
        Assert.Contains("OLE Package", result.Message);
    }

    [Fact]
    public async Task ModernScan_EquationEditorObject_IsDetected()
    {
        var ole = TestFiles.Cfb(4096, (1536, TestFiles.Utf16("Equation Native")));

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/oleObject2.bin", ole));

        Assert.False(result.IsClean);
        Assert.Contains("Equation", result.Message);
    }

    [Fact]
    public async Task ModernScan_EmbeddedLegacyDocumentWithVba_IsDetected()
    {
        var doc = TestFiles.Cfb(8192, (2048, TestFiles.Utf16("_VBA_PROJECT")));

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/Microsoft_Word_97_-_2003_Document.doc", doc));

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_NestedMacroEnabledPackage_IsDetected()
    {
        var inner = OoxmlBuilder.Word(macroEnabled: true).Build();

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/Microsoft_Word_Document.docx", inner));

        Assert.False(result.IsClean);
        Assert.Contains("Embedded package", result.Message);
    }

    [Fact]
    public async Task ModernScan_PayloadInsidePlainEmbeddedZip_IsDetected()
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            using var s = zip.CreateEntry("readme.txt").Open();
            s.Write(PeLikeHeader);
        }

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/archive.zip", ms.ToArray()));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task ModernScan_PackagesNestedTooDeeply_FailsClosed()
    {
        var package = OoxmlBuilder.Word().Build();
        for (int level = 0; level < 5; level++)
            package = OoxmlBuilder.Word().Part("word/embeddings/Microsoft_Word_Document.docx", package).Build();

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/Microsoft_Word_Document.docx", package));

        Assert.False(result.IsClean);
        Assert.Contains("nested too deeply", result.Message);
    }

    // No false positives for ordinary embedded objects.
    [Fact]
    public async Task ModernScan_BenignEmbeddedWorkbookAndOleObject_IsClean()
    {
        var builder = OoxmlBuilder.Word()
            .Part("word/embeddings/Microsoft_Excel_Worksheet.xlsx", OoxmlBuilder.Excel().Build())
            .Part("word/embeddings/oleObject1.bin", TestFiles.Cfb(4096, (512, TestFiles.Utf16("Workbook"))));

        var result = await Scan(builder);

        Assert.True(result.IsClean, result.Message);
    }
}
