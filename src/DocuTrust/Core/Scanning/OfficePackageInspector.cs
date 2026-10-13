using System.Buffers;
using System.IO.Compression;
using System.Xml;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// First pass over an OOXML package: reads every part through a <see cref="BoundedReadStream"/> so the real
/// decompressed size, the shared budget and the compression ratio are enforced before any parser sees the package,
/// and determines the document kind from the package's own content types.
/// </summary>
internal sealed class OfficePackageInspector
{
    private const string ContentTypesEntry = "[Content_Types].xml";
    private const string RootRelationshipsEntry = "_rels/.rels";

    private const string VbaMessage = "VBA Macros detected in package.";
    private const string XlmMessage = "Excel 4.0 (XLM) macro sheet detected in package.";

    // Office finds macro code through content types and relationships, not file names (MS-OFFMACRO2, MS-OI29500).
    private static readonly string[] VbaContentTypeMarkers = ["macroEnabled", "vbaProject", "vbaData"];
    private static readonly string[] XlmContentTypeMarkers = ["macrosheet"];
    private static readonly string[] VbaRelationshipSuffixes = ["/vbaProject", "/vbaProjectSignature", "/wordVbaData"];
    private static readonly string[] XlmRelationshipSuffixes = ["/xlMacrosheet", "/xlIntlMacrosheet"];

    private static readonly HashSet<string> MaliciousExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".vbs", ".ps1", ".bat", ".com", ".scr", ".js", ".jse", ".wsf", ".wsh", ".vbe", ".jar"
    };

    private readonly ArrayPool<byte> _pool;
    private readonly OfficeScanLimits _limits;

    public OfficePackageInspector(ArrayPool<byte> pool, OfficeScanLimits limits)
    {
        _pool = pool;
        _limits = limits;
    }

    /// <summary>Inspects the package. Requires a seekable stream.</summary>
    public async Task<OfficePackageVerdict> InspectAsync(Stream stream, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var preflight = ZipPreflight.Check(stream, _limits.MaxEntries, _pool, token);
        if (preflight != null)
            return Threat(preflight);

        var budget = new ScanBudget(_limits.MaxTotalUncompressedBytes);
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            if (zip.Entries.Count > _limits.MaxEntries)
                return Threat("Package contains excessive number of parts.");

            var contentTypesEntry = Find(zip, ContentTypesEntry);
            var rootRelsEntry = Find(zip, RootRelationshipsEntry);
            if (contentTypesEntry == null || rootRelsEntry == null)
                return Threat("Package is not a valid Office Open XML document.");

            PackageModel model;
            using (var part = OpenBounded(contentTypesEntry, budget))
                model = PackageModel.ParseContentTypes(part);

            List<PackageRelationship> rootRelationships;
            using (var part = OpenBounded(rootRelsEntry, budget))
                rootRelationships = PackageModel.ParseRelationships(part);

            var contentTypeThreat = MacroContentTypeThreat(model);
            if (contentTypeThreat != null)
                return Threat(contentTypeThreat);

            var rootThreat = MacroRelationshipThreat(rootRelationships);
            if (rootThreat != null)
                return Threat(rootThreat);

            foreach (var entry in zip.Entries)
            {
                token.ThrowIfCancellationRequested();

                if (entry.Length > _limits.MaxPartBytes)
                    return Threat($"Part '{entry.FullName}' exceeds safety size limit.");

                var nameThreat = MacroPartNameThreat(entry.FullName);
                if (nameThreat != null)
                    return Threat(nameThreat);

                if (entry.FullName.Contains("embeddings/"))
                {
                    string ext = Path.GetExtension(entry.FullName).ToLowerInvariant();
                    if (MaliciousExts.Contains(ext))
                        return Threat($"Suspicious embedded executable found: {entry.FullName}");
                }

                if (entry == contentTypesEntry || entry == rootRelsEntry)
                    continue;

                if (entry.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                {
                    List<PackageRelationship> relationships;
                    using (var part = OpenBounded(entry, budget))
                        relationships = PackageModel.ParseRelationships(part);

                    var relationshipThreat = MacroRelationshipThreat(relationships);
                    if (relationshipThreat != null)
                        return Threat(relationshipThreat);
                    continue;
                }

                await DrainAsync(entry, budget, token).ConfigureAwait(false);
            }

            // The main part is the target of the root officeDocument relationship (transitional or strict).
            var main = rootRelationships.FirstOrDefault(r => !r.IsExternal
                && r.Type.EndsWith("/officeDocument", StringComparison.OrdinalIgnoreCase));
            var kind = main.Type == null
                ? OfficeDocumentKind.Unknown
                : PackageModel.KindOf(model.ContentTypeOf(PackageModel.ToPartName(main.Target)));

            return kind == OfficeDocumentKind.Unknown
                ? Threat("Package is not a recognised Word, Excel or PowerPoint document.")
                : new OfficePackageVerdict(null, kind);
        }
        catch (ScanLimitExceededException ex)
        {
            return Threat(ex.Message);
        }
        catch (InvalidDataException)
        {
            return Threat("Package contains a corrupt or unreadable part.");
        }
        catch (XmlException)
        {
            return Threat("Package contains malformed XML.");
        }
    }

    private static string? MacroContentTypeThreat(PackageModel model)
    {
        foreach (var contentType in model.AllContentTypes)
        {
            if (XlmContentTypeMarkers.Any(m => contentType.Contains(m, StringComparison.OrdinalIgnoreCase)))
                return XlmMessage;
            if (VbaContentTypeMarkers.Any(m => contentType.Contains(m, StringComparison.OrdinalIgnoreCase)))
                return VbaMessage;
        }
        return null;
    }

    private static string? MacroRelationshipThreat(IEnumerable<PackageRelationship> relationships)
    {
        foreach (var relationship in relationships)
        {
            if (XlmRelationshipSuffixes.Any(s => relationship.Type.EndsWith(s, StringComparison.OrdinalIgnoreCase)))
                return XlmMessage;
            if (VbaRelationshipSuffixes.Any(s => relationship.Type.EndsWith(s, StringComparison.OrdinalIgnoreCase)))
                return VbaMessage;
        }
        return null;
    }

    private static string? MacroPartNameThreat(string entryName)
    {
        var name = PackageModel.ToPartName(entryName);
        if (name.EndsWith("/vbaProject.bin", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("/vbaProjectSignature.bin", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("/vbaData.xml", StringComparison.OrdinalIgnoreCase))
            return VbaMessage;
        if (name.Contains("/macrosheets/", StringComparison.OrdinalIgnoreCase))
            return XlmMessage;
        return null;
    }

    private static OfficePackageVerdict Threat(string message) => new(message, OfficeDocumentKind.Unknown);

    private static ZipArchiveEntry? Find(ZipArchive zip, string name)
        => zip.Entries.FirstOrDefault(e => string.Equals(e.FullName, name, StringComparison.OrdinalIgnoreCase));

    private BoundedReadStream OpenBounded(ZipArchiveEntry entry, ScanBudget budget)
        => new(entry.Open(), _limits.MaxPartBytes, budget, entry.CompressedLength,
            _limits.MaxCompressionRatio, _limits.CompressionRatioThresholdBytes);

    private async Task DrainAsync(ZipArchiveEntry entry, ScanBudget budget, CancellationToken token)
    {
        await using var part = OpenBounded(entry, budget);
        await PooledChunkReader.ReadAsync(part, _pool, overlap: 0, long.MaxValue, static (_, _) => false, token)
            .ConfigureAwait(false);
    }
}
