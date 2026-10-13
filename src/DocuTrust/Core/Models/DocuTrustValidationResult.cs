namespace DocuTrust.Core.Models;

/// <summary>
/// The outcome of a call to <see cref="DocuTrust.Core.Abstractions.IDocuTrustFileValidator"/>.
/// </summary>
/// <example>
/// <code>
/// var result = await validator.ValidateFileAsync(file, ".pdf");
/// Console.WriteLine($"{result.IsValid}: {result.ActualMimeType} ({result.ActualExtension}) {result.Message}");
/// </code>
/// </example>
public class DocuTrustValidationResult
{
    /// <summary>
    /// <see langword="true"/> when the file passed the check. For
    /// <see cref="DocuTrust.Core.Abstractions.IDocuTrustFileValidator.GetFileTypeAsync"/> it means the format was recognised.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// The MIME type detected from the file's signature, for example <c>application/pdf</c>.
    /// <see langword="null"/> when the format is not recognised or the file was rejected before inspection.
    /// </summary>
    public string? ActualMimeType { get; set; }

    /// <summary>
    /// The extension detected from the file's signature, without the leading dot (for example <c>pdf</c>).
    /// <see langword="null"/> when the format is not recognised or the file was rejected before inspection.
    /// </summary>
    public string? ActualExtension { get; set; }

    /// <summary>
    /// A short explanation of the outcome, prefixed with <c>[DocuTrust]</c>. It never contains file content or
    /// the client file name, so it is safe to return to the caller.
    /// </summary>
    public string? Message { get; set; }
}
