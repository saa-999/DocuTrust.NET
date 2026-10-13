namespace DocuTrust.Core.Models;

/// <summary>
/// The result of a content scan or a page text extraction.
/// </summary>
/// <remarks>
/// The PDF and Office content scanners that produce this type are internal in this version, so public code
/// cannot obtain an instance from DocuTrust yet. The type stays public for compatibility.
/// </remarks>
/// <example>
/// <code>
/// // Reading a result: only IsScanned together with IsClean means the content passed.
/// bool passed = check.IsScanned &amp;&amp; check.IsClean;
/// </code>
/// </example>
public class DocuTrustFileCheckResult
{
    /// <summary>
    /// <see langword="true"/> when the scan found no threat. A file that was not fully scanned is never clean.
    /// </summary>
    public bool IsClean { get; set; }

    /// <summary>
    /// <see langword="true"/> when the document is encrypted or password protected.
    /// </summary>
    public bool IsEncrypted { get; set; }

    /// <summary>
    /// <see langword="true"/> when the scan ran to completion. <see langword="false"/> after a time limit, a size
    /// limit or a parse failure.
    /// </summary>
    public bool IsScanned { get; set; }

    /// <summary>
    /// Reserved. The current scanners never set it, so it is always <see langword="false"/>.
    /// </summary>
    public bool EncryptionPermissions { get; set; }

    /// <summary>
    /// The text extracted from the requested page or pages, or <see langword="null"/> when no text was extracted.
    /// </summary>
    public string? Page { get; set; }

    /// <summary>
    /// A short explanation of the outcome.
    /// </summary>
    public string? Message { get; set; }
}
