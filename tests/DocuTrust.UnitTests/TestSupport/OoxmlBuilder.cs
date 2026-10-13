using System.IO.Compression;
using System.Security;
using System.Text;

namespace DocuTrust.Tests.TestSupport;

/// <summary>
/// Builds minimal OOXML packages byte-for-byte so tests control every part, content type and relationship.
/// All payloads are benign markers.
/// </summary>
internal sealed class OoxmlBuilder
{
    public const string WordNs = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    public const string SheetNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    public const string PresentationNs = "http://schemas.openxmlformats.org/presentationml/2006/main";
    public const string DrawingNs = "http://schemas.openxmlformats.org/drawingml/2006/main";
    public const string RelNs = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    public const string OfficeDocumentRel = RelNs + "/officeDocument";

    private readonly List<(string Name, byte[] Data)> _parts = new();
    private readonly Dictionary<string, string> _defaults = new(StringComparer.OrdinalIgnoreCase)
    {
        ["rels"] = "application/vnd.openxmlformats-package.relationships+xml",
        ["xml"] = "application/xml",
    };
    private readonly Dictionary<string, string> _overrides = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _rels = new(StringComparer.Ordinal);

    public string MainPart { get; private set; } = "";

    public static OoxmlBuilder Word(string bodyXml = "<w:p><w:r><w:t>hello world</w:t></w:r></w:p>", bool macroEnabled = false)
    {
        var b = new OoxmlBuilder { MainPart = "word/document.xml" };
        b.Part("word/document.xml", $"<w:document xmlns:w=\"{WordNs}\" xmlns:r=\"{RelNs}\"><w:body>{bodyXml}</w:body></w:document>",
            macroEnabled ? "application/vnd.ms-word.document.macroEnabled.main+xml"
                         : "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml");
        b.Rel("", "rId1", OfficeDocumentRel, "word/document.xml");
        return b;
    }

    public static OoxmlBuilder Excel(string sheetDataXml = "<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>cell text</t></is></c></row>")
    {
        var b = new OoxmlBuilder { MainPart = "xl/workbook.xml" };
        b.Part("xl/workbook.xml", $"<workbook xmlns=\"{SheetNs}\" xmlns:r=\"{RelNs}\"><sheets><sheet name=\"S1\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml");
        b.Part("xl/worksheets/sheet1.xml", $"<worksheet xmlns=\"{SheetNs}\"><sheetData>{sheetDataXml}</sheetData></worksheet>",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml");
        b.Rel("", "rId1", OfficeDocumentRel, "xl/workbook.xml");
        b.Rel("xl/workbook.xml", "rId1", RelNs + "/worksheet", "worksheets/sheet1.xml");
        return b;
    }

    public static OoxmlBuilder PowerPoint(string slideShapesXml = "<p:sp><p:txBody><a:p><a:r><a:t>slide text</a:t></a:r></a:p></p:txBody></p:sp>")
    {
        var b = new OoxmlBuilder { MainPart = "ppt/presentation.xml" };
        b.Part("ppt/presentation.xml", $"<p:presentation xmlns:p=\"{PresentationNs}\" xmlns:r=\"{RelNs}\"><p:sldIdLst><p:sldId id=\"256\" r:id=\"rId1\"/></p:sldIdLst></p:presentation>",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml");
        b.Part("ppt/slides/slide1.xml", $"<p:sld xmlns:p=\"{PresentationNs}\" xmlns:a=\"{DrawingNs}\" xmlns:r=\"{RelNs}\"><p:cSld><p:spTree>{slideShapesXml}</p:spTree></p:cSld></p:sld>",
            "application/vnd.openxmlformats-officedocument.presentationml.slide+xml");
        b.Rel("", "rId1", OfficeDocumentRel, "ppt/presentation.xml");
        b.Rel("ppt/presentation.xml", "rId1", RelNs + "/slide", "slides/slide1.xml");
        return b;
    }

    public OoxmlBuilder Part(string name, string content, string? contentType = null)
        => Part(name, Encoding.UTF8.GetBytes(content), contentType);

    public OoxmlBuilder Part(string name, byte[] content, string? contentType = null)
    {
        _parts.RemoveAll(p => p.Name == name);
        _parts.Add((name, content));
        if (contentType != null)
            _overrides["/" + name] = contentType;
        return this;
    }

    public OoxmlBuilder Default(string extension, string contentType)
    {
        _defaults[extension] = contentType;
        return this;
    }

    /// <summary>Adds a relationship from <paramref name="sourcePart"/> ("" for the package root).</summary>
    public OoxmlBuilder Rel(string sourcePart, string id, string type, string target, bool external = false)
    {
        if (!_rels.TryGetValue(sourcePart, out var list))
            _rels[sourcePart] = list = new List<string>();
        list.Add($"<Relationship Id=\"{id}\" Type=\"{SecurityElement.Escape(type)}\" Target=\"{SecurityElement.Escape(target)}\"{(external ? " TargetMode=\"External\"" : "")}/>");
        return this;
    }

    public byte[] Build(CompressionLevel level = CompressionLevel.Optimal)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var ct = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
            foreach (var (ext, type) in _defaults)
                ct.Append($"<Default Extension=\"{ext}\" ContentType=\"{type}\"/>");
            foreach (var (name, type) in _overrides)
                ct.Append($"<Override PartName=\"{name}\" ContentType=\"{type}\"/>");
            ct.Append("</Types>");
            Write(zip, "[Content_Types].xml", Encoding.UTF8.GetBytes(ct.ToString()), level);

            foreach (var (source, rels) in _rels)
            {
                string relsName = source.Length == 0
                    ? "_rels/.rels"
                    : $"{Path.GetDirectoryName(source)!.Replace('\\', '/')}/_rels/{Path.GetFileName(source)}.rels";
                var xml = $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">{string.Concat(rels)}</Relationships>";
                Write(zip, relsName, Encoding.UTF8.GetBytes(xml), level);
            }

            foreach (var (name, data) in _parts)
                Write(zip, name, data, level);
        }
        return ms.ToArray();
    }

    private static void Write(ZipArchive zip, string name, byte[] data, CompressionLevel level)
    {
        var entry = zip.CreateEntry(name, level);
        using var s = entry.Open();
        s.Write(data);
    }
}
