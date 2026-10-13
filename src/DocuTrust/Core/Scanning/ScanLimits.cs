using DocuTrust.Core.Constants;

namespace DocuTrust.Core.Scanning;

/// <summary>Thrown when a resource limit is hit while reading untrusted content. The message is safe to surface.</summary>
internal sealed class ScanLimitExceededException : Exception
{
    public ScanLimitExceededException(string message) : base(message)
    {
    }
}

/// <summary>Decompressed-byte budget shared by every part (and nested package) of one scan.</summary>
internal sealed class ScanBudget
{
    public ScanBudget(long totalBytes)
    {
        Remaining = totalBytes;
    }

    public long Remaining { get; private set; }

    public void Consume(int bytes)
    {
        Remaining -= bytes;
        if (Remaining < 0)
            throw new ScanLimitExceededException("Package exceeds the total decompressed size budget (zip bomb protection).");
    }
}

/// <summary>Resource limits for OOXML package scanning. Defaults come from <see cref="FileSize"/>; tests may lower them.</summary>
internal sealed class OfficeScanLimits
{
    public static OfficeScanLimits Default { get; } = new();

    public int MaxEntries { get; init; } = FileSize.MaxPackageEntries;

    public long MaxPartBytes { get; init; } = FileSize.MaxPartSizeBytes;

    public long MaxTotalUncompressedBytes { get; init; } = FileSize.MaxTotalUncompressedBytes;

    public int MaxCompressionRatio { get; init; } = FileSize.MaxCompressionRatio;

    public long CompressionRatioThresholdBytes { get; init; } = FileSize.CompressionRatioThresholdBytes;

    public int MaxNestedPackageDepth { get; init; } = FileSize.MaxNestedPackageDepth;

    public int MaxExtractedTextChars { get; init; } = FileSize.MaxExtractedTextChars;
}

/// <summary>Resource limits for PDF scanning and extraction. Defaults come from <see cref="FileSize"/>; tests may lower them.</summary>
internal sealed class PdfScanLimits
{
    public static PdfScanLimits Default { get; } = new();

    public int MaxPages { get; init; } = FileSize.MaxPdfPages;

    public int MaxLettersPerPage { get; init; } = FileSize.MaxPdfLettersPerPage;

    public int MaxExtractedTextChars { get; init; } = FileSize.MaxExtractedTextChars;

    public int MaxObjects { get; init; } = FileSize.MaxPdfObjects;
}
