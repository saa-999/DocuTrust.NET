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
    /// <param name="token">Cancellation token for async operations.</param>
    /// <returns>Validation result including MIME type and extension matches.</returns>
    /// <remarks>
    /// <para><b>Security:</b> the path is trusted input. Never pass a path built from user input without first
    /// canonicalising it (<see cref="System.IO.Path.GetFullPath(string)"/>) and checking it stays inside your upload
    /// directory: DocuTrust does not prevent path traversal. Symbolic links are followed to their final target. On
    /// Windows a UNC path (<c>\\host\share</c>) makes the process authenticate to that host (NTLM credential leak).</para>
    /// <para>Targets that are empty or not regular files (FIFOs, character devices, most <c>/proc</c> entries) are
    /// rejected without being opened, because opening a FIFO blocks indefinitely.</para>
    /// </remarks>
    Task<DocuTrustValidationResult> ValidateFilePathAsync(string filePath, string expectedExtension , CancellationToken token = default );

    /// <summary>
    /// Validates a raw stream of data.
    /// </summary>
    /// <param name="fileStream">The stream to check.</param>
    /// <param name="expectedExtension">What it's supposed to be.</param>
    /// <param name="token">Cancellation token for async operations.</param>
    /// <returns>Validation result.</returns>
    Task<DocuTrustValidationResult> ValidateFileStreamAsync(Stream fileStream, string expectedExtension , CancellationToken token = default);

    /// <summary>
    /// Tries to figure out what a file actually is by looking at its signature.
    /// </summary>
    /// <param name="filePath">Path to the file.</param>
    /// <param name="token">Cancellation token for async operations.</param>
    /// <returns>Information about the detected file type.</returns>
    /// <remarks>
    /// <para><b>Security:</b> the path is trusted input. Never pass a path built from user input without first
    /// canonicalising it (<see cref="System.IO.Path.GetFullPath(string)"/>) and checking it stays inside your upload
    /// directory: DocuTrust does not prevent path traversal. Symbolic links are followed to their final target. On
    /// Windows a UNC path (<c>\\host\share</c>) makes the process authenticate to that host (NTLM credential leak).</para>
    /// <para>Targets that are empty or not regular files (FIFOs, character devices, most <c>/proc</c> entries) are
    /// rejected without being opened, because opening a FIFO blocks indefinitely.</para>
    /// </remarks>
    Task<DocuTrustValidationResult> GetFileTypeAsync(string filePath , CancellationToken token = default);

    /// <summary>
    /// Validates an IFormFile (typically from an ASP.NET Core upload).
    /// </summary>
    /// <param name="file">The uploaded file.</param>
    /// <param name="expectedExtension">Expected extension (required; an empty value fails validation).</param>
    /// <param name="token">Cancellation token for async operations.</param>
    /// <returns>Validation result.</returns>
    /// <remarks>
    /// Checks the magic bytes against <paramref name="expectedExtension"/> and, when the client file name has an
    /// extension, that it matches too. Validation identifies the file type only: it does not scan content for
    /// macros or scripts. Never store or serve an upload under the client-supplied name.
    /// </remarks>
    Task<DocuTrustValidationResult> ValidateFileAsync(IFormFile file, string expectedExtension , CancellationToken token = default);
}
