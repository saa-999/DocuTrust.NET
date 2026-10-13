using System.Xml;

namespace DocuTrust.Core.Scanning;

internal enum OfficeDocumentKind
{
    Unknown,
    Word,
    Excel,
    PowerPoint,
}

/// <summary>Outcome of <see cref="OfficePackageInspector"/>: a threat message (null when clean) and the document kind.</summary>
internal readonly record struct OfficePackageVerdict(string? Threat, OfficeDocumentKind Kind);

/// <summary>One relationship as written in a <c>.rels</c> part (raw, unresolved).</summary>
internal readonly record struct PackageRelationship(string Type, string Target, bool IsExternal);

/// <summary>Content types of an OPC package, resolved the way Office resolves them (Override first, then Default).</summary>
internal sealed class PackageModel
{
    private readonly Dictionary<string, string> _defaults = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _overrides = new(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<string> AllContentTypes => _defaults.Values.Concat(_overrides.Values);

    /// <summary>Normalises a ZIP entry name or relationship target to an OPC part name ("/word/document.xml").</summary>
    public static string ToPartName(string name)
    {
        var normalized = name.Replace('\\', '/');
        return normalized.StartsWith('/') ? normalized : "/" + normalized;
    }

    public string? ContentTypeOf(string partName)
    {
        if (_overrides.TryGetValue(partName, out var type))
            return type;

        var extension = Path.GetExtension(partName);
        return extension.Length > 1 && _defaults.TryGetValue(extension[1..], out type) ? type : null;
    }

    public static PackageModel ParseContentTypes(Stream stream)
    {
        var model = new PackageModel();
        using var reader = SafeXml.Create(stream);
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element)
                continue;

            var contentType = reader.GetAttribute("ContentType");
            if (contentType == null)
                continue;

            if (reader.LocalName == "Default" && reader.GetAttribute("Extension") is { } extension)
                model._defaults[extension.TrimStart('.')] = contentType;
            else if (reader.LocalName == "Override" && reader.GetAttribute("PartName") is { } partName)
                model._overrides[ToPartName(partName)] = contentType;
        }
        return model;
    }

    public static List<PackageRelationship> ParseRelationships(Stream stream)
    {
        var relationships = new List<PackageRelationship>();
        using var reader = SafeXml.Create(stream);
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "Relationship")
                continue;

            relationships.Add(new PackageRelationship(
                reader.GetAttribute("Type") ?? string.Empty,
                reader.GetAttribute("Target") ?? string.Empty,
                string.Equals(reader.GetAttribute("TargetMode"), "External", StringComparison.OrdinalIgnoreCase)));
        }
        return relationships;
    }

    /// <summary>Maps the main part's content type to a document kind (transitional, strict and macro-enabled variants).</summary>
    public static OfficeDocumentKind KindOf(string? mainContentType)
    {
        if (mainContentType == null)
            return OfficeDocumentKind.Unknown;
        if (mainContentType.Contains("wordprocessingml", StringComparison.OrdinalIgnoreCase)
            || mainContentType.StartsWith("application/vnd.ms-word", StringComparison.OrdinalIgnoreCase))
            return OfficeDocumentKind.Word;
        if (mainContentType.Contains("spreadsheetml", StringComparison.OrdinalIgnoreCase)
            || mainContentType.StartsWith("application/vnd.ms-excel", StringComparison.OrdinalIgnoreCase))
            return OfficeDocumentKind.Excel;
        if (mainContentType.Contains("presentationml", StringComparison.OrdinalIgnoreCase)
            || mainContentType.StartsWith("application/vnd.ms-powerpoint", StringComparison.OrdinalIgnoreCase))
            return OfficeDocumentKind.PowerPoint;
        return OfficeDocumentKind.Unknown;
    }
}
