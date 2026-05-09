namespace DocuTrust.Core.Constants;

internal static class FileSize
{
    public const long MaxFileSizeBytes = 100 * 1024 * 1024;
    public const long MaxPdfSizeBytes = 150 * 1024 * 1024;
    public const long MaxPartSizeBytes = 20 * 1024 * 1024;
    public const int MaxPackageEntries = 5000;
    public const long MaxEmbeddedStreamSize = 25 * 1024 * 1024;
    public const int MaxNestingDepth = 15;
    
}
