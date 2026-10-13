using System.Buffers;
using System.IO.Compression;
using System.Xml;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// First pass over an OOXML package: reads every part through a <see cref="BoundedReadStream"/> so the real
/// decompressed size, the shared budget and the compression ratio are enforced before any parser sees the package,
/// determines the document kind from the package's own content types, and inspects every part's content.
/// </summary>
internal sealed class OfficePackageInspector
{
    private const string ContentTypesEntry = "[Content_Types].xml";
    private const string RootRelationshipsEntry = "_rels/.rels";
    private const string VbaMessage = "VBA Macros detected in package.";
    private const string XlmMessage = "Excel 4.0 (XLM) macro sheet detected in package.";
    private const string ExecutableMessage = "Suspicious embedded executable found in package.";
    private const string OlePackageMessage = "Embedded OLE Package object (file carrier) detected in package.";
    private const string EquationMessage = "Embedded Equation Editor object detected in package.";

    // Office finds macro code through content types and relationships, not file names (MS-OFFMACRO2, MS-OI29500).
    private static readonly string[] VbaContentTypeMarkers = ["macroEnabled", "vbaProject", "vbaData"];
    private static readonly string[] XlmContentTypeMarkers = ["macrosheet"];
    private static readonly string[] VbaRelationshipSuffixes = ["/vbaProject", "/vbaProjectSignature", "/wordVbaData"];
    private static readonly string[] XlmRelationshipSuffixes = ["/xlMacrosheet", "/xlIntlMacrosheet"];

    // Executables, scripts, shortcuts, installers, disk images and macro-enabled Office types, anywhere in the package.
    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".drv", ".ocx",
        ".msi", ".msp", ".mst", ".msc", ".msix", ".msixbundle", ".appx", ".appxbundle", ".application", ".appref-ms", ".gadget",
        ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".wsc", ".ps1", ".psm1", ".psd1", ".sh",
        ".hta", ".sct", ".chm", ".jar", ".reg", ".inf", ".scf", ".lnk", ".url",
        ".library-ms", ".search-ms", ".searchconnector-ms", ".settingcontent-ms", ".diagcab",
        ".iso", ".img", ".vhd", ".vhdx", ".cab",
        ".xll", ".xla", ".xlam", ".ppam", ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppsm", ".sldm",
    };

    // Stream/storage names inside embedded OLE (CFB) objects. Matched as ASCII and UTF-16LE.
    private const string OleNativeStream = "\u0001Ole10Native";
    private const string EquationNativeStream = "Equation Native";
    private static readonly KeywordSet OleIndicators = new(
        ["_VBA_PROJECT", "VBAProject", "PROJECTwm", OleNativeStream, EquationNativeStream]);

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

        var budget = new ScanBudget(_limits.MaxTotalUncompressedBytes);
        try
        {
            return await InspectPackageAsync(stream, depth: 0, budget, token).ConfigureAwait(false);
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

    private async Task<OfficePackageVerdict> InspectPackageAsync(Stream stream, int depth, ScanBudget budget, CancellationToken token)
    {
        var preflight = ZipPreflight.Check(stream, _limits.MaxEntries, _pool, token);
        if (preflight != null)
            return Threat(preflight);

        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Count > _limits.MaxEntries)
            return Threat("Package contains excessive number of parts.");

        var contentTypesEntry = Find(zip, ContentTypesEntry);
        var rootRelsEntry = Find(zip, RootRelationshipsEntry);

        // The uploaded file itself must be an OPC package; embedded archives may be plain ZIPs.
        if (depth == 0 && (contentTypesEntry == null || rootRelsEntry == null))
            return Threat("Package is not a valid Office Open XML document.");

        PackageModel model = PackageModel.Empty;
        if (contentTypesEntry != null)
        {
            using var part = OpenBounded(contentTypesEntry, budget);
            model = PackageModel.ParseContentTypes(part);
        }

        var rootRelationships = new List<PackageRelationship>();
        if (rootRelsEntry != null)
        {
            using var part = OpenBounded(rootRelsEntry, budget);
            rootRelationships = PackageModel.ParseRelationships(part);
        }

        var packageThreat = MacroContentTypeThreat(model) ?? MacroRelationshipThreat(rootRelationships);
        if (packageThreat != null)
            return Threat(packageThreat);

        foreach (var entry in zip.Entries)
        {
            token.ThrowIfCancellationRequested();

            if (entry.Length > _limits.MaxPartBytes)
                return Threat($"Part '{entry.FullName}' exceeds safety size limit.");

            var nameThreat = MacroPartNameThreat(entry.FullName);
            if (nameThreat != null)
                return Threat(nameThreat);

            if (DangerousExtensions.Contains(Path.GetExtension(entry.FullName.TrimEnd('.', ' '))))
                return Threat($"Suspicious embedded executable found: {entry.FullName}");

            if (entry == contentTypesEntry || entry == rootRelsEntry)
                continue;

            string? partThreat;
            if (entry.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
            {
                using var part = OpenBounded(entry, budget);
                partThreat = MacroRelationshipThreat(PackageModel.ParseRelationships(part));
            }
            else
            {
                partThreat = await InspectPartContentAsync(entry, model, depth, budget, token).ConfigureAwait(false);
            }

            if (partThreat != null)
                return Threat(partThreat);
        }

        if (depth > 0)
            return new OfficePackageVerdict(null, OfficeDocumentKind.Unknown);

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

    /// <summary>Classifies a part by its leading bytes (never by its name) and inspects it accordingly.</summary>
    private async Task<string?> InspectPartContentAsync(ZipArchiveEntry entry, PackageModel model, int depth, ScanBudget budget, CancellationToken token)
    {
        var magic = new byte[8];
        int length;
        await using (var peek = OpenBounded(entry, budget))
            length = await peek.ReadAtLeastAsync(magic, magic.Length, throwOnEndOfStream: false, token).ConfigureAwait(false);

        var content = Classify(magic.AsSpan(0, length));
        if (content == PartContent.Other && LooksLikeXml(entry.FullName, model, magic.AsSpan(0, length)))
            content = PartContent.Xml;

        switch (content)
        {
            case PartContent.Executable:
                return ExecutableMessage;
            case PartContent.OleCompoundFile:
                return await ScanEmbeddedOleAsync(entry, budget, token).ConfigureAwait(false);
            case PartContent.ZipArchive:
                return await InspectNestedPackageAsync(entry, depth, budget, token).ConfigureAwait(false);
            case PartContent.Xml:
                await using (var part = OpenBounded(entry, budget))
                {
                    var threat = OfficeXmlContentScanner.Scan(part, token);
                    if (threat != null)
                        return threat;
                    await DrainAsync(part, token).ConfigureAwait(false);
                }
                return null;
            default:
                await DrainAsync(entry, budget, token).ConfigureAwait(false);
                return null;
        }
    }

    private enum PartContent
    {
        Other,
        Executable,
        OleCompoundFile,
        ZipArchive,
        Xml,
    }

    private async Task<string?> ScanEmbeddedOleAsync(ZipArchiveEntry entry, ScanBudget budget, CancellationToken token)
    {
        string? indicator = null;
        await using (var part = OpenBounded(entry, budget))
        {
            await PooledChunkReader.ReadAsync(
                part, _pool, OleIndicators.MaxPatternLength - 1, long.MaxValue,
                (window, _) => (indicator = OleIndicators.FindFirst(window)) != null,
                token).ConfigureAwait(false);
        }

        return indicator switch
        {
            null => null,
            OleNativeStream => OlePackageMessage,
            EquationNativeStream => EquationMessage,
            _ => VbaMessage,
        };
    }

    private async Task<string?> InspectNestedPackageAsync(ZipArchiveEntry entry, int depth, ScanBudget budget, CancellationToken token)
    {
        if (depth + 1 > _limits.MaxNestedPackageDepth)
            return "Embedded packages are nested too deeply.";

        // ZipArchive needs a seekable stream; the copy is bounded by the part limit and the shared budget.
        using var copy = new MemoryStream((int)Math.Min(entry.Length, _limits.MaxPartBytes));
        await using (var part = OpenBounded(entry, budget))
        {
            // Not Stream.CopyToAsync: its pooled buffer goes back to the shared pool uncleared.
            await PooledChunkReader.ReadAsync(
                part, _pool, overlap: 0, long.MaxValue,
                (window, _) => { copy.Write(window); return false; },
                token).ConfigureAwait(false);
        }
        copy.Position = 0;

        var nested = await InspectPackageAsync(copy, depth + 1, budget, token).ConfigureAwait(false);
        return nested.Threat == null ? null : $"Embedded package rejected: {nested.Threat}";
    }

    private static ReadOnlySpan<byte> CfbMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private static ReadOnlySpan<byte> ZipMagic => [0x50, 0x4B, 0x03, 0x04];

    private static ReadOnlySpan<byte> ElfMagic => [0x7F, 0x45, 0x4C, 0x46];

    private static ReadOnlySpan<byte> ShortcutMagic => [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];

    /// <summary>
    /// A part is parsed as XML when its declared content type or extension says so, or when it starts like XML,
    /// so renaming a part cannot hide markup that Office would still load.
    /// </summary>
    private static bool LooksLikeXml(string entryName, PackageModel model, ReadOnlySpan<byte> header)
    {
        var contentType = model.ContentTypeOf(PackageModel.ToPartName(entryName));
        if (contentType != null && (contentType.EndsWith("+xml", StringComparison.OrdinalIgnoreCase)
                                    || contentType.EndsWith("/xml", StringComparison.OrdinalIgnoreCase)))
            return true;

        var extension = Path.GetExtension(entryName);
        if (extension.Equals(".xml", StringComparison.OrdinalIgnoreCase) || extension.Equals(".vml", StringComparison.OrdinalIgnoreCase))
            return true;

        if (header.StartsWith(Utf16LittleEndianBom) || header.StartsWith(Utf16BigEndianBom))
            return true;
        if (header.StartsWith(Utf8Bom))
            header = header[3..];
        header = header.TrimStart(" \t\r\n"u8);
        return !header.IsEmpty && header[0] == (byte)'<';
    }

    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    private static ReadOnlySpan<byte> Utf16LittleEndianBom => [0xFF, 0xFE];

    private static ReadOnlySpan<byte> Utf16BigEndianBom => [0xFE, 0xFF];

    private static PartContent Classify(ReadOnlySpan<byte> header)
    {
        if (header.StartsWith("MZ"u8) || header.StartsWith(ElfMagic) || header.StartsWith(ShortcutMagic))
            return PartContent.Executable;                                       // PE, ELF, Windows shortcut
        if (header.Length >= 4
            && System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header) is
                0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xCAFEBABE)
            return PartContent.Executable;                                       // Mach-O, fat binary / Java class
        if (header.StartsWith(CfbMagic))
            return PartContent.OleCompoundFile;
        if (header.StartsWith(ZipMagic))
            return PartContent.ZipArchive;
        return PartContent.Other;
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
        await DrainAsync(part, token).ConfigureAwait(false);
    }

    /// <summary>Reads the rest of a part so every decompressed byte is counted against the limits.</summary>
    private Task DrainAsync(Stream part, CancellationToken token)
        => PooledChunkReader.ReadAsync(part, _pool, overlap: 0, long.MaxValue, static (_, _) => false, token);
}
