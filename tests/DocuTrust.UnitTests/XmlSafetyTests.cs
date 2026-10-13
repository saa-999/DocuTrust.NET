using System.Text;
using System.Xml;
using DocuTrust.Core.Scanning;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>
/// Regression tests for DT-041: every XML path refuses DTDs, so neither external entities (XXE) nor entity
/// expansion can be reached. The external entity points at a real temp file to show it is never resolved.
/// </summary>
public sealed class XmlSafetyTests : IDisposable
{
    private readonly string _secretFile = Path.Combine(Path.GetTempPath(), $"docutrust-secret-{Guid.NewGuid():N}.txt");

    public XmlSafetyTests() => File.WriteAllText(_secretFile, "DDEAUTO SecretService topic");

    public void Dispose() => File.Delete(_secretFile);

    private string ExternalEntityDocument(string root)
        => $"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file://{_secretFile}\">]>{root}";

    [Fact]
    public void SafeXml_RejectsDocumentTypeDefinitions()
    {
        var xml = ExternalEntityDocument("<r>&xxe;</r>");
        using var reader = SafeXml.Create(new MemoryStream(Encoding.UTF8.GetBytes(xml)));

        Assert.Throws<XmlException>(() => { while (reader.Read()) { } });
    }

    [Fact]
    public void SafeXml_RejectsEntityExpansion()
    {
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><r>&b;</r>";
        using var reader = SafeXml.Create(new MemoryStream(Encoding.UTF8.GetBytes(xml)));

        Assert.Throws<XmlException>(() => { while (reader.Read()) { } });
    }

    [Theory]
    [InlineData("word/document.xml")]
    [InlineData("word/_rels/document.xml.rels")]
    [InlineData("[Content_Types].xml")]
    public async Task OfficeScan_ExternalEntityInAnyXmlPart_FailsClosedWithoutResolving(string partName)
    {
        var builder = OoxmlBuilder.Word();
        var bytes = builder.Build();
        // Replace the chosen part's bytes with a DTD-bearing document after the package has been built.
        bytes = ReplaceEntry(bytes, partName, ExternalEntityDocument("<r>&xxe;</r>"));

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(bytes, "a.docx"));

        Assert.False(result.IsClean);
        Assert.DoesNotContain("DDE", result.Message); // the entity's content was never read
    }

    private static byte[] ReplaceEntry(byte[] package, string name, string content)
    {
        using var ms = new MemoryStream();
        ms.Write(package);
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Update, leaveOpen: true))
        {
            zip.GetEntry(name)?.Delete();
            using var s = zip.CreateEntry(name).Open();
            s.Write(Encoding.UTF8.GetBytes(content));
        }
        return ms.ToArray();
    }
}
