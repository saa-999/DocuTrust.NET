using UglyToad.PdfPig.Tokens;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// Rules applied to every PDF dictionary the scanner inspects. Names are compared case-insensitively (stricter
/// than ISO 32000, which is case-sensitive) so case variants cannot slip past. PdfPig has already decoded
/// <c>#xx</c> escapes in names. Messages are constant text: no attacker-controlled value is echoed.
/// </summary>
internal static class PdfThreatRules
{
    private static readonly Dictionary<string, string> DangerousKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["JS"] = "JavaScript code (/JS) detected.",
        ["JavaScript"] = "JavaScript name tree detected.",
        ["AA"] = "Automatic trigger (/AA additional actions) detected.",
        ["XFA"] = "XFA form (scriptable) detected.",
        ["EmbeddedFiles"] = "Embedded files (payload carrier) detected.",
        ["EF"] = "Embedded file specification (/EF) detected.",
        ["RichMediaContent"] = "RichMedia content detected.",
        ["RichMediaSettings"] = "RichMedia content detected.",
    };

    private static readonly Dictionary<string, string> DangerousActions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["JavaScript"] = "Embedded JavaScript detected.",
        ["JS"] = "Embedded JavaScript detected.",
        ["Launch"] = "External process launch command (/Launch) detected.",
        ["GoToR"] = "Remote resource action (/GoToR) detected.",
        ["ImportData"] = "Remote resource action (/ImportData) detected.",
        ["GoToE"] = "Embedded-document action (/GoToE) detected.",
        ["SubmitForm"] = "Form submission action (/SubmitForm) detected.",
        ["Rendition"] = "Multimedia action (/Rendition) detected.",
        ["RichMediaExecute"] = "Multimedia action (/RichMediaExecute) detected.",
        ["Sound"] = "Multimedia action (/Sound) detected.",
        ["Movie"] = "Multimedia action (/Movie) detected.",
    };

    private static readonly Dictionary<string, string> DangerousSubtypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["FileAttachment"] = "File attachment annotation detected.",
        ["RichMedia"] = "Active annotation (/RichMedia) detected.",
        ["Screen"] = "Active annotation (/Screen) detected.",
        ["Movie"] = "Active annotation (/Movie) detected.",
        ["Sound"] = "Active annotation (/Sound) detected.",
        ["3D"] = "Active annotation (/3D) detected.",
    };

    private static readonly HashSet<string> SafeUriSchemes = new(StringComparer.Ordinal) { "http", "https", "mailto" };

    /// <summary>Returns a constant threat message for the first rule the dictionary breaks, or null.</summary>
    public static string? Inspect(DictionaryToken dictionary)
    {
        foreach (var (key, value) in dictionary.Data)
        {
            if (DangerousKeys.TryGetValue(key, out var keyThreat))
                return keyThreat;

            if (key.Equals("S", StringComparison.OrdinalIgnoreCase) && NameOf(value) is { } action)
            {
                if (DangerousActions.TryGetValue(action, out var actionThreat))
                    return actionThreat;
                if (action.Equals("URI", StringComparison.OrdinalIgnoreCase) && IsDangerousUri(dictionary))
                    return "URI action with a script, file, UNC or non-web scheme detected.";
            }
            else if (key.Equals("Subtype", StringComparison.OrdinalIgnoreCase) && NameOf(value) is { } subtype
                     && DangerousSubtypes.TryGetValue(subtype, out var subtypeThreat))
            {
                return subtypeThreat;
            }
            else if (key.Equals("Type", StringComparison.OrdinalIgnoreCase)
                     && string.Equals(NameOf(value), "EmbeddedFile", StringComparison.OrdinalIgnoreCase))
            {
                return "Embedded file stream detected.";
            }
        }
        return null;
    }

    private static string? NameOf(IToken? token) => token switch
    {
        NameToken name => name.Data,
        StringToken text => text.Data,
        _ => null,
    };

    private static bool IsDangerousUri(DictionaryToken action)
    {
        var uri = action.Data.FirstOrDefault(kv => kv.Key.Equals("URI", StringComparison.OrdinalIgnoreCase)).Value switch
        {
            StringToken text => text.Data,
            HexToken hex => hex.Data,
            null => null,
            _ => string.Empty, // not a string (e.g. an indirect stream): cannot be validated, fail closed
        };
        if (uri == null)
            return false;

        var target = new string(uri.Where(c => !char.IsWhiteSpace(c) && !char.IsControl(c)).ToArray());
        if (target.Length == 0 && uri.Length > 0)
            return true;
        if (target.StartsWith(@"\\", StringComparison.Ordinal) || target.StartsWith("//", StringComparison.Ordinal))
            return true;

        int colon = target.IndexOf(':');
        if (colon <= 0)
            return false; // relative URI, resolved against the document base

        var scheme = target[..colon];
        bool isScheme = char.IsAsciiLetter(scheme[0]) && scheme.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.');
        if (!isScheme)
            return false; // e.g. "page.html?x=a:b" is relative

        // Single letters are drive letters ("C:\..."): a local file path.
        return !SafeUriSchemes.Contains(scheme.ToLowerInvariant());
    }
}
