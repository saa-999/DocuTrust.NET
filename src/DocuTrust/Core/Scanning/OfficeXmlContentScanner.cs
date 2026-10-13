using System.Text;
using System.Xml;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// Streams one OOXML XML part (any part: body, headers, footnotes, comments, glossary, sheets, slides…) and
/// looks for active content: Word field codes (DDE), Excel DDE links and DDE formulas.
/// Malformed XML or a DTD throws <see cref="XmlException"/>, which callers treat as a failed (not clean) scan.
/// </summary>
internal static class OfficeXmlContentScanner
{
    private const char NestedFieldMarker = '\u0001';
    private const int MaxFieldNesting = 32;
    private const int MaxCapturedChars = 64 * 1024;

    private const string DdeMessage = "DDE/DDEAUTO field code detected.";
    private const string DynamicFieldMessage = "Field code whose type is computed by a nested field (obfuscation) detected.";
    private const string ExcelDdeMessage = "Excel DDE link or DDE formula detected.";
    private const string ExcelOleLinkMessage = "Excel external OLE link detected.";

    private static readonly HashSet<string> SpreadsheetNamespaces = new(StringComparer.Ordinal)
    {
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
        "http://purl.oclc.org/ooxml/spreadsheetml/main",
    };

    public static string? Scan(Stream stream, CancellationToken token)
    {
        using var reader = SafeXml.Create(stream);

        var fields = new Stack<StringBuilder?>();        // open complex fields; null once past "separate"
        StringBuilder? capture = null;                    // text of the element being captured
        var captureKind = Capture.None;
        long nodes = 0;

        while (reader.Read())
        {
            if ((++nodes & 0x3FF) == 0)
                token.ThrowIfCancellationRequested();

            switch (reader.NodeType)
            {
                case XmlNodeType.Element:
                {
                    var name = reader.LocalName;
                    switch (name)
                    {
                        case "fldSimple":
                            if (CheckInstruction(GetAttribute(reader, "instr")) is { } simpleThreat)
                                return simpleThreat;
                            break;

                        case "fldChar":
                            var type = GetAttribute(reader, "fldCharType");
                            if (string.Equals(type, "begin", StringComparison.OrdinalIgnoreCase))
                            {
                                if (fields.Count >= MaxFieldNesting)
                                    return "Field codes are nested too deeply.";
                                if (fields.Count > 0)
                                    fields.Peek()?.Append(NestedFieldMarker);
                                fields.Push(new StringBuilder());
                            }
                            else if (fields.Count > 0 && (string.Equals(type, "separate", StringComparison.OrdinalIgnoreCase)
                                                          || string.Equals(type, "end", StringComparison.OrdinalIgnoreCase)))
                            {
                                var instruction = fields.Pop();
                                if (instruction != null && CheckInstruction(instruction.ToString()) is { } fieldThreat)
                                    return fieldThreat;
                                if (string.Equals(type, "separate", StringComparison.OrdinalIgnoreCase))
                                    fields.Push(null); // result region until "end"
                            }
                            break;

                        case "instrText":
                        case "delInstrText":
                            if (!reader.IsEmptyElement)
                            {
                                capture = fields.Count > 0 && fields.Peek() != null ? fields.Peek() : new StringBuilder();
                                captureKind = fields.Count > 0 && fields.Peek() != null ? Capture.FieldInstruction : Capture.LooseInstruction;
                            }
                            break;

                        case "ddeLink":
                            return ExcelDdeMessage;

                        case "oleLink":
                            return ExcelOleLinkMessage;

                        case "hlinkClick":
                        case "hlinkHover":
                        case "hlinkMouseOver":
                        case "cNvPr":
                            if (GetAttribute(reader, "action") is { } action
                                && (action.StartsWith("ppaction://program", StringComparison.OrdinalIgnoreCase)
                                    || action.StartsWith("ppaction://macro", StringComparison.OrdinalIgnoreCase)))
                                return "PowerPoint run-program/macro action (ppaction) detected.";
                            break;

                        case "f":
                        case "definedName":
                            if (!reader.IsEmptyElement && SpreadsheetNamespaces.Contains(reader.NamespaceURI))
                            {
                                capture = new StringBuilder();
                                captureKind = Capture.Formula;
                            }
                            break;
                    }
                    break;
                }

                case XmlNodeType.Text:
                case XmlNodeType.CDATA:
                case XmlNodeType.Whitespace:
                case XmlNodeType.SignificantWhitespace:
                    if (capture != null)
                    {
                        capture.Append(reader.Value);
                        if (capture.Length > MaxCapturedChars)
                            return "Field code or formula exceeds the inspection size limit.";
                    }
                    break;

                case XmlNodeType.EndElement:
                    if (capture != null && reader.LocalName is "instrText" or "delInstrText" or "f" or "definedName")
                    {
                        var text = capture.ToString();
                        var kind = captureKind;
                        capture = null;
                        captureKind = Capture.None;

                        if (kind == Capture.LooseInstruction && CheckInstruction(text) is { } looseThreat)
                            return looseThreat;
                        if (kind == Capture.Formula && IsDdeFormula(text))
                            return ExcelDdeMessage;
                    }
                    break;
            }
        }

        // Fields left open at the end of the part are still evaluated.
        foreach (var open in fields)
        {
            if (open != null && CheckInstruction(open.ToString()) is { } openThreat)
                return openThreat;
        }
        return null;
    }

    /// <summary>Checks a complete field instruction. Word field names are case-insensitive.</summary>
    internal static string? CheckInstruction(string? instruction)
    {
        if (string.IsNullOrEmpty(instruction))
            return null;

        var text = instruction.AsSpan().TrimStart(" \t\r\n\"' ".AsSpan());
        if (text.IsEmpty)
            return null;

        // The field type itself comes from a nested field (e.g. QUOTE with character codes): treat as obfuscation.
        if (text[0] == NestedFieldMarker)
            return DynamicFieldMessage;

        int end = text.IndexOfAny(" \t\r\n\"\\ ".AsSpan());
        var fieldType = end < 0 ? text : text[..end];
        if (fieldType.Equals("DDE", StringComparison.OrdinalIgnoreCase)
            || fieldType.Equals("DDEAUTO", StringComparison.OrdinalIgnoreCase))
            return DdeMessage;

        return null;
    }

    /// <summary>
    /// In Excel formulas '|' only appears outside string literals and quoted sheet names in DDE references
    /// (<c>service|'topic'!item</c>).
    /// </summary>
    internal static bool IsDdeFormula(string formula)
    {
        bool inString = false, inSheetName = false;
        foreach (char c in formula)
        {
            if (c == '"' && !inSheetName)
                inString = !inString;
            else if (c == '\'' && !inString)
                inSheetName = !inSheetName;
            else if (c == '|' && !inString && !inSheetName)
                return true;
        }
        return false;
    }

    private static string? GetAttribute(XmlReader reader, string localName)
    {
        if (!reader.HasAttributes)
            return null;

        string? value = null;
        while (reader.MoveToNextAttribute())
        {
            if (reader.LocalName == localName)
            {
                value = reader.Value;
                break;
            }
        }
        reader.MoveToElement();
        return value;
    }

    private enum Capture
    {
        None,
        FieldInstruction,
        LooseInstruction,
        Formula,
    }
}
