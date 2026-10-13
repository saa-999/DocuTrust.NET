using UglyToad.PdfPig;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Tokens;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// Walks every object reachable from the document catalog — pages, annotations and their popups/parents,
/// outlines (bookmarks), name trees, form fields, optional content, and objects stored inside compressed object
/// streams — and applies <see cref="PdfThreatRules"/> to each dictionary. Iterative, with a visited set and
/// limits on object count and inline nesting depth; exceeding a limit fails closed.
/// </summary>
internal static class PdfStructureWalker
{
    private const int MaxInlineDepth = 64;

    // Subtrees that cannot hold actions (content streams, fonts, images, tagged-structure trees) are not followed:
    // they hold most of a file's bytes and objects, and readers never execute actions found there.
    private static readonly HashSet<string> SkippedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Contents", "Resources", "Thumb", "Metadata", "StructTreeRoot",
        "FontFile", "FontFile2", "FontFile3", "ToUnicode", "CIDToGIDMap",
    };

    public static string? FindThreat(PdfDocument pdf, CancellationToken token, int maxObjects)
    {
        var visited = new HashSet<IndirectReference>();
        var pending = new Stack<(IToken Token, int Depth)>();
        pending.Push((pdf.Structure.Catalog.CatalogDictionary, 0));
        int objects = 0;
        long steps = 0;

        while (pending.Count > 0)
        {
            if ((++steps & 0x3FF) == 0)
                token.ThrowIfCancellationRequested();

            var (current, depth) = pending.Pop();
            if (depth > MaxInlineDepth)
                return "PDF object nesting exceeds the inspection limits.";

            switch (current)
            {
                case IndirectReferenceToken reference:
                    if (!visited.Add(reference.Data))
                        break;
                    if (++objects > maxObjects)
                        return "PDF object graph exceeds the inspection limits.";
                    if (Resolve(pdf, reference.Data) is { } resolved)
                        pending.Push((resolved, 0));
                    break;

                case StreamToken stream:
                    if (Visit(stream.StreamDictionary, depth, pending) is { } streamThreat)
                        return streamThreat;
                    break;

                case DictionaryToken dictionary:
                    if (Visit(dictionary, depth, pending) is { } threat)
                        return threat;
                    break;

                case ArrayToken array:
                    foreach (var item in array.Data)
                        pending.Push((item, depth + 1));
                    break;
            }
        }
        return null;
    }

    private static string? Visit(DictionaryToken dictionary, int depth, Stack<(IToken Token, int Depth)> pending)
    {
        if (PdfThreatRules.Inspect(dictionary) is { } threat)
            return threat;

        foreach (var (key, value) in dictionary.Data)
        {
            if (!SkippedKeys.Contains(key))
                pending.Push((value, depth + 1));
        }
        return null;
    }

    private static IToken? Resolve(PdfDocument pdf, IndirectReference reference)
    {
        try
        {
            return pdf.Structure.GetObject(reference)?.Data;
        }
        catch (InvalidOperationException ex) when (ex.Message.StartsWith("Could not find the object", StringComparison.Ordinal))
        {
            // ISO 32000-1 §7.3.10: a reference to an undefined object is the null object, not an error.
            // Any other parse failure propagates and the scan fails closed.
            return null;
        }
    }
}
