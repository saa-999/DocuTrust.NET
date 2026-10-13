using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-012 (DDE / field-code detection). Service names are benign placeholders.</summary>
public class OfficeDdeDetectionTests
{
    private const string W = OoxmlBuilder.WordNs;

    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(OoxmlBuilder builder, string name = "upload.docx")
        => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(builder.Build(), name));

    private static string ComplexField(params string[] instructionRuns)
        => "<w:p><w:r><w:fldChar w:fldCharType=\"begin\"/></w:r>"
           + string.Concat(instructionRuns.Select(i => $"<w:r><w:instrText xml:space=\"preserve\">{i}</w:instrText></w:r>"))
           + "<w:r><w:fldChar w:fldCharType=\"separate\"/></w:r><w:r><w:t>result</w:t></w:r><w:r><w:fldChar w:fldCharType=\"end\"/></w:r></w:p>";

    [Fact]
    public async Task ModernScan_DdeInComplexField_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word(ComplexField(" DDEAUTO BenignService \"topic\" ")));

        Assert.False(result.IsClean);
        Assert.Contains("DDE", result.Message);
    }

    [Fact]
    public async Task ModernScan_DdeInFldSimple_IsDetected()
    {
        var body = "<w:p><w:fldSimple w:instr=\" DDEAUTO BenignService &quot;topic&quot; \"><w:r><w:t>x</w:t></w:r></w:fldSimple></w:p>";

        var result = await Scan(OoxmlBuilder.Word(body));

        Assert.False(result.IsClean);
        Assert.Contains("DDE", result.Message);
    }

    [Fact]
    public async Task ModernScan_LowercaseDde_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word(ComplexField(" ddeauto BenignService topic ")));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task ModernScan_DdeSplitAcrossRuns_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Word(ComplexField(" DD", "EAUTO BenignService ", "\"topic\"")));

        Assert.False(result.IsClean);
        Assert.Contains("DDE", result.Message);
    }

    [Fact]
    public async Task ModernScan_FieldTypeFromNestedQuoteField_IsDetected()
    {
        // { { QUOTE 68 68 69 } BenignService topic }: the outer field's type is produced at runtime.
        var body = "<w:p><w:r><w:fldChar w:fldCharType=\"begin\"/></w:r>"
                 + "<w:r><w:fldChar w:fldCharType=\"begin\"/></w:r><w:r><w:instrText> QUOTE 68 68 69 </w:instrText></w:r>"
                 + "<w:r><w:fldChar w:fldCharType=\"separate\"/></w:r><w:r><w:fldChar w:fldCharType=\"end\"/></w:r>"
                 + "<w:r><w:instrText> BenignService topic </w:instrText></w:r>"
                 + "<w:r><w:fldChar w:fldCharType=\"separate\"/></w:r><w:r><w:fldChar w:fldCharType=\"end\"/></w:r></w:p>";

        var result = await Scan(OoxmlBuilder.Word(body));

        Assert.False(result.IsClean);
        Assert.Contains("nested field", result.Message);
    }

    [Theory]
    [InlineData("word/footnotes.xml", "footnotes", "footnote")]
    [InlineData("word/endnotes.xml", "endnotes", "endnote")]
    [InlineData("word/comments.xml", "comments", "comment")]
    [InlineData("word/glossary/document.xml", "document", "body")]
    public async Task ModernScan_DdeOutsideMainBody_IsDetected(string partName, string root, string child)
    {
        var xml = $"<w:{root} xmlns:w=\"{W}\"><w:{child}>{ComplexField(" DDE BenignService topic ")}</w:{child}></w:{root}>";

        var result = await Scan(OoxmlBuilder.Word().Part(partName, xml));

        Assert.False(result.IsClean);
        Assert.Contains("DDE", result.Message);
    }

    [Fact]
    public async Task ModernScan_ExcelDdeLink_IsDetected()
    {
        var link = $"<externalLink xmlns=\"{OoxmlBuilder.SheetNs}\"><ddeLink ddeService=\"BenignService\" ddeTopic=\"topic\"/></externalLink>";

        var result = await Scan(OoxmlBuilder.Excel().Part("xl/externalLinks/externalLink1.xml", link), "book.xlsx");

        Assert.False(result.IsClean);
        Assert.Contains("DDE", result.Message);
    }

    [Fact]
    public async Task ModernScan_ExcelDdeFormula_IsDetected()
    {
        var result = await Scan(OoxmlBuilder.Excel("<row r=\"1\"><c r=\"A1\"><f>BenignService|'topic'!A0</f></c></row>"), "book.xlsx");

        Assert.False(result.IsClean);
        Assert.Contains("DDE", result.Message);
    }

    // The old DDE check swallowed parse errors (catch {}) and reported the document clean.
    [Fact]
    public async Task ModernScan_MalformedXmlPart_FailsClosed()
    {
        var result = await Scan(OoxmlBuilder.Word().Part("word/footnotes.xml", $"<w:footnotes xmlns:w=\"{W}\"><w:footnote>"));

        Assert.False(result.IsClean);
    }

    [Fact]
    public async Task ModernScan_BodyWithDoctype_FailsClosed()
    {
        var package = OoxmlBuilder.Word();
        package.Part("word/document.xml",
            $"<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY e \"x\">]><w:document xmlns:w=\"{W}\"><w:body>{ComplexField(" DDE BenignService topic ")}</w:body></w:document>",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml");

        var result = await Scan(package);

        Assert.False(result.IsClean);
    }

    // No false positives for ordinary fields and formulas.
    [Fact]
    public async Task ModernScan_OrdinaryFieldsAndFormulas_AreClean()
    {
        var word = OoxmlBuilder.Word(ComplexField(" PAGE ") + ComplexField(" MERGEFIELD Hidden ") + "<w:p><w:fldSimple w:instr=\" HYPERLINK &quot;https://example.com&quot; \"/></w:p>");
        var excel = OoxmlBuilder.Excel("<row r=\"1\"><c r=\"A1\"><f>SUM(B1:B2)&amp;\"a|b\"&amp;'Sheet|2'!A1</f></c></row>");

        var wordResult = await Scan(word);
        var excelResult = await Scan(excel, "book.xlsx");

        Assert.True(wordResult.IsClean, wordResult.Message);
        Assert.True(excelResult.IsClean, excelResult.Message);
    }
}
