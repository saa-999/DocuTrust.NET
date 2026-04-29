namespace DocuTrust.Core.Models;

/// <summary>
/// The outcome of a file validation, including detected MIME types and extensions.
/// </summary>
public class DocuTrustValidationResult
{
    /// <summary>
    /// True if the file matches what we expected.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// What the file actually claims to be (MIME type).
    /// </summary>
    public string? ActualMimeType { get; set; }

    /// <summary>
    /// The extension we found by looking at the file's magic bytes.
    /// </summary>
    public string? ActualExtension { get; set; }

    /// <summary>
    /// Friendly explanation of the validation result.
    /// </summary>
    public string? Message { get; set; }
}
