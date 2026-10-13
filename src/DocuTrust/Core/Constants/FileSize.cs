namespace DocuTrust.Core.Constants;

internal static class FileSize
{
    public const long MaxFileSizeBytes = 100 * 1024 * 1024;
    public const long MaxPdfSizeBytes = 150 * 1024 * 1024;
    public const long MaxPartSizeBytes = 20 * 1024 * 1024;
    public const int MaxPackageEntries = 5000;
    public const long MaxEmbeddedStreamSize = 25 * 1024 * 1024;
    public const int MaxNestingDepth = 15;

    /// <summary>Total bytes that may be decompressed from one package, nested packages included.</summary>
    public const long MaxTotalUncompressedBytes = 256L * 1024 * 1024;

    /// <summary>Largest allowed uncompressed/compressed ratio for a package part.</summary>
    public const int MaxCompressionRatio = 100;

    /// <summary>Parts smaller than this are not subject to the ratio check (tiny XML compresses extremely well).</summary>
    public const long CompressionRatioThresholdBytes = 1L * 1024 * 1024;

    /// <summary>How many levels of packages embedded in packages are inspected before failing closed.</summary>
    public const int MaxNestedPackageDepth = 3;

    /// <summary>Most characters text extraction returns before failing closed (about 20 MB of UTF-16).</summary>
    public const int MaxExtractedTextChars = 10_000_000;

    /// <summary>Most pages a PDF may have for whole-document text extraction.</summary>
    public const int MaxPdfPages = 5_000;

    /// <summary>Most glyphs on one PDF page before word extraction (super-linear in glyph count) is refused.</summary>
    public const int MaxPdfLettersPerPage = 500_000;

    /// <summary>Most indirect objects the structural PDF walk visits before failing closed.</summary>
    public const int MaxPdfObjects = 200_000;
    
}
