using System.Diagnostics;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-013 (suspicious relationships and traversal cost). Targets are benign placeholders.</summary>
public class OfficeRelationshipTests
{
    private const string AttachedTemplate = OoxmlBuilder.RelNs + "/attachedTemplate";
    private const string FrameRel = OoxmlBuilder.RelNs + "/frame";
    private const string SubDocumentRel = OoxmlBuilder.RelNs + "/subDocument";
    private const string OleObjectRel = OoxmlBuilder.RelNs + "/oleObject";
    private const string HyperlinkRel = OoxmlBuilder.RelNs + "/hyperlink";

    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(OoxmlBuilder builder, string name = "upload.docx")
        => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(builder.Build(), name));

    [Fact]
    public async Task ModernScan_RemoteHttpTemplate_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdT", AttachedTemplate, "https://example.invalid/evil.dotm", external: true);

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("template", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ModernScan_RemoteFrame_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdF", FrameRel, "https://example.invalid/frame.docx", external: true);

        Assert.False((await Scan(builder)).IsClean);
    }

    [Fact]
    public async Task ModernScan_RemoteSubDocument_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdS", SubDocumentRel, "https://example.invalid/part.docx", external: true);

        Assert.False((await Scan(builder)).IsClean);
    }

    [Fact]
    public async Task ModernScan_UncHyperlinkTarget_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdU", HyperlinkRel, @"\\placeholder-host\share\x", external: true);

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("UNC", result.Message);
    }

    [Theory]
    [InlineData("ms-msdt:/id PCWDiagnostic")]  // Follina-class protocol handler (no payload)
    [InlineData("search-ms://query")]
    [InlineData("ms-word:ofe%7Cu%7Chttps://example.invalid/x.docx")]
    [InlineData("file:///etc/placeholder")]
    [InlineData("mhtml:https://example.invalid/x")]
    [InlineData("its:placeholder")]
    public async Task ModernScan_ProtocolHandlerHyperlink_IsDetected(string target)
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdP", HyperlinkRel, target, external: true);

        var result = await Scan(builder);

        Assert.False(result.IsClean);
        Assert.Contains("scheme", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ModernScan_ExternalOleObject_IsDetected()
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdO", OleObjectRel, "https://example.invalid/o.bin", external: true);

        Assert.False((await Scan(builder)).IsClean);
    }

    [Fact]
    public async Task ModernScan_PowerPointRunProgramAction_IsDetected()
    {
        var shapes = "<p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"x\"><a:hlinkClick xmlns:a=\""
                     + OoxmlBuilder.DrawingNs + "\" r:id=\"\" action=\"ppaction://program\"/></p:cNvPr></p:nvSpPr></p:sp>";

        var result = await Scan(OoxmlBuilder.PowerPoint(shapes), "deck.pptx");

        Assert.False(result.IsClean);
        Assert.Contains("ppaction", result.Message);
    }

    // DT-013 point 1: shared parts referenced many times must not cause exponential traversal.
    [Fact]
    public async Task ModernScan_HeavilyCrossReferencedParts_CompletesQuickly()
    {
        var builder = OoxmlBuilder.Word();
        // 40 parts, each with a .rels pointing at every other part: O(n^2) edges, exponential only without a single pass.
        for (int i = 0; i < 40; i++)
        {
            builder.Part($"word/p{i}.xml", "<x/>");
            var rels = string.Concat(Enumerable.Range(0, 40).Select(j => $"<Relationship Id=\"r{i}_{j}\" Type=\"{HyperlinkRel}\" Target=\"p{j}.xml\"/>"));
            builder.Part($"word/_rels/p{i}.xml.rels",
                $"<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">{rels}</Relationships>",
                "application/vnd.openxmlformats-package.relationships+xml");
        }

        var sw = Stopwatch.StartNew();
        var result = await Scan(builder);
        sw.Stop();

        Assert.True(result.IsClean, result.Message);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"traversal took {sw.Elapsed}");
    }

    // No false positives for ordinary internal relationships and http hyperlinks.
    [Fact]
    public async Task ModernScan_OrdinaryHyperlinksAndInternalRels_AreClean()
    {
        var builder = OoxmlBuilder.Word()
            .Rel("word/document.xml", "rIdH", HyperlinkRel, "https://example.com/page", external: true)
            .Rel("word/document.xml", "rIdM", HyperlinkRel, "mailto:someone@example.com", external: true)
            .Part("word/header1.xml", $"<w:hdr xmlns:w=\"{OoxmlBuilder.WordNs}\"/>", "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml")
            .Rel("word/document.xml", "rIdHdr", OoxmlBuilder.RelNs + "/header", "header1.xml");

        var result = await Scan(builder);

        Assert.True(result.IsClean, result.Message);
    }
}
