using Microsoft.AspNetCore.Http;
using DocuTrust.Core.Models;

namespace DocuTrust.Core.Abstractions;

/// <summary>
/// The main validator interface. Handles everything from checking file extensions to verifying magic bytes.
/// </summary>
public interface IDocuTrustFileValidator
{
    /// <summary>
    /// Validates a file sitting on the disk.
    /// </summary>
    /// <param name="filePath">Full path to the file.</param>
    /// <param name="expectedExtension">What extension we're expecting (e.g., ".pdf").</param>
    /// <returns>Validation result including MIME type and extension matches.</returns>
    Task<DocuTrustValidationResult> ValidateFilePathAsync(string filePath, string expectedExtension);

    /// <summary>
    /// Validates a raw stream of data.
    /// </summary>
    /// <param name="fileStream">The stream to check.</param>
    /// <param name="expectedExtension">What it's supposed to be.</param>
    /// <returns>Validation result.</returns>
    Task<DocuTrustValidationResult> ValidateFileStreamAsync(Stream fileStream, string expectedExtension);

    /// <summary>
    /// Tries to figure out what a file actually is by looking at its signature.
    /// </summary>
    /// <param name="filePath">Path to the file.</param>
    /// <returns>Information about the detected file type.</returns>
    Task<DocuTrustValidationResult> GetFileTypeAsync(string filePath);

    /// <summary>
    /// Validates an IFormFile (typically from an ASP.NET Core upload).
    /// </summary>
    /// <param name="file">The uploaded file.</param>
    /// <param name="expectedExtension">Expected extension.</param>
    /// <returns>Validation result.</returns>
    Task<DocuTrustValidationResult> ValidateFileAsync(IFormFile file, string expectedExtension);
}
