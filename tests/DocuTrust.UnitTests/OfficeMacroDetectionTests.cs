using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-010 (macro detection beyond the literal name vbaProject.bin).</summary>
public class OfficeMacroDetectionTests
{
    private const string VbaProjectRel = "http://schemas.microsoft.com/office/2006/relationships/vbaProject";
    private const string WordVbaDataRel = "http://schemas.microsoft.com/office/2006/relationships/wordVbaData";
    private const string XlMacrosheetRel = "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet";
    private static readonly byte[] BenignBlob = TestFiles.Ascii("benign stand-in, not a real VBA project");

    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(OoxmlBuilder builder, string name = "upload.docx")
        => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(builder.Build(), name));

    [Fact]
    public async Task ModernScan_LiteralVbaProjectName_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word().Part("word/vbaProject.bin", BenignBlob));

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_RenamedVbaProjectReferencedByRelationship_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Default("dat", "application/octet-stream")
            .Part("word/payload.dat", BenignBlob)
            .Rel("word/document.xml", "rId9", VbaProjectRel, "payload.dat");

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_RenamedVbaProjectDeclaredByContentType_IsDetected()
    {
        var builder = OoxmlBuilder.Word().Part("word/payload.dat", BenignBlob, "application/vnd.ms-office.vbaProject");

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_MacroEnabledMainContentType_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word(macroEnabled: true), "upload.docm");

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_VbaDataPartByName_IsDetected()
    {
        var builder = OoxmlBuilder.Word().Part("word/vbaData.xml", "<wne:vbaSuppData xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\"/>");

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_VbaDataRelationship_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Part("word/settings2.xml", "<x/>")
            .Rel("word/document.xml", "rId8", WordVbaDataRel, "settings2.xml");

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("VBA", result.Message);
    }

    [Fact]
    public async Task ModernScan_Excel4MacroSheetByPath_IsDetected()
    {
        var builder = OoxmlBuilder.Excel().Part("xl/macrosheets/sheet1.xml", "<xm:macrosheet xmlns:xm=\"http://schemas.microsoft.com/office/excel/2006/main\"/>");

        var result = await Scan(builder, "book.xlsx");

        Assert.False(result.IsClean);
        Assert.Contains("XLM", result.Message);
    }

    [Fact]
    public async Task ModernScan_Excel4MacroSheetByRelationship_IsDetected()
    {
        var builder = OoxmlBuilder.Excel()
            .Part("xl/worksheets/sheet2.xml", "<x/>")
            .Rel("xl/workbook.xml", "rId2", XlMacrosheetRel, "worksheets/sheet2.xml");

        var result = await Scan(builder, "book.xlsx");

        Assert.False(result.IsClean);
        Assert.Contains("XLM", result.Message);
    }

    [Fact]
    public async Task ModernScan_Excel4MacroSheetByContentType_IsDetected()
    {
        var builder = OoxmlBuilder.Excel().Part("xl/worksheets/sheet2.xml", "<x/>", "application/vnd.ms-excel.intlmacrosheet+xml");

        var result = await Scan(builder, "book.xlsx");

        Assert.False(result.IsClean);
        Assert.Contains("XLM", result.Message);
    }
}
