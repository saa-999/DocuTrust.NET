using System.Buffers;
using DocuTrust.Core.Scanning;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-017: text extraction must not report IsClean = true without scanning.</summary>
public class OfficeTextExtractionTests
{
    private static Task<Core.Models.DocuTrustFileCheckResult> GetPage(byte[] content, string name, OfficeScanLimits? limits = null)
        => new DocuTrustOfficeScanner(ArrayPool<byte>.Shared, limits ?? OfficeScanLimits.Default)
            .GetPageAsync(1, 1, TestFiles.FormFile(content, name));

    [Fact]
    public async Task GetPage_MacroEnabledDocument_IsNotCleanAndReturnsNoText()
    {
        var result = await GetPage(OoxmlBuilder.Word(macroEnabled: true).Build(), "a.docm");

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_LegacyDocumentWithMacroIndicator_IsNotClean()
    {
        var result = await GetPage(TestFiles.Cfb(8192, (3000, TestFiles.Utf16("AutoOpen"))), "a.doc");

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_NonOfficeBinary_FailsClosed()
    {
        var result = await GetPage(TestFiles.Ascii("MZ-benign stand-in, not an Office document at all"), "a.doc");

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_CleanWordDocument_ReturnsTextAndIsClean()
    {
        var result = await GetPage(OoxmlBuilder.Word().Build(), "a.docx");

        Assert.True(result.IsClean, result.Message);
        Assert.Contains("hello world", result.Page);
    }

    [Fact]
    public async Task GetPage_TextBeyondLimit_FailsClosed()
    {
        var body = $"<w:p><w:r><w:t>{new string('x', 500)}</w:t></w:r></w:p>";

        var result = await GetPage(OoxmlBuilder.Word(body).Build(), "a.docx", new OfficeScanLimits { MaxExtractedTextChars = 100 });

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_LegacyTextBeyondLimit_FailsClosed()
    {
        var result = await GetPage(TestFiles.Cfb(8192), "a.doc", new OfficeScanLimits { MaxExtractedTextChars = 100 });

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task GetPage_WorkbookWithChartsheet_ExtractsWorksheetText()
    {
        var builder = OoxmlBuilder.Excel()
            .Part("xl/workbook.xml",
                $"<workbook xmlns=\"{OoxmlBuilder.SheetNs}\" xmlns:r=\"{OoxmlBuilder.RelNs}\"><sheets>"
                + "<sheet name=\"Chart\" sheetId=\"2\" r:id=\"rId2\"/><sheet name=\"S1\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
            .Part("xl/chartsheets/sheet2.xml", $"<chartsheet xmlns=\"{OoxmlBuilder.SheetNs}\"/>",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml")
            .Rel("xl/workbook.xml", "rId2", OoxmlBuilder.RelNs + "/chartsheet", "chartsheets/sheet2.xml");

        var result = await GetPage(builder.Build(), "book.xlsx");

        Assert.True(result.IsClean, result.Message);
        Assert.Contains("cell text", result.Page);
    }
}
