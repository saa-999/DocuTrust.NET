using Microsoft.AspNetCore.Http;
using DocuTrust.Core.Models;

namespace DocuTrust.Core.Abstractions;

/// <summary>
/// Checks that a file's content matches the type it claims to be, using its magic bytes (file signature)
/// instead of its name.
/// </summary>
/// <remarks>
/// Register the default implementation, <see cref="DocuTrust.Core.Services.DocuTrustFileScanner"/>, with
/// <see cref="DocuTrust.Extensions.DocuTrustExtensions.AddDocuTrust"/>. A file of the wrong type is not an error:
/// the returned <see cref="DocuTrustValidationResult.IsValid"/> is <see langword="false"/>. Invalid arguments and
/// I/O failures surface as <see cref="DocuTrust.Exceptions.DocuTrustValidationException"/>.
/// </remarks>
/// <example>
/// <code>
/// builder.Services.AddDocuTrust();
///
/// app.MapPost("/upload", async (IFormFile file, IDocuTrustFileValidator validator) =>
/// {
///     var result = await validator.ValidateFileAsync(file, ".pdf");
///     return result.IsValid ? Results.Ok() : Results.BadRequest(result.Message);
/// }).DisableAntiforgery();
/// </code>
/// </example>
public interface IDocuTrustFileValidator
{
    /// <summary>
    /// Checks that the file at <paramref name="filePath"/> has the signature of <paramref name="expectedExtension"/>.
    /// </summary>
    /// <param name="filePath">Path to the file. It must come from your application, not from user input.</param>
    /// <param name="expectedExtension">The extension the file should have, with or without the leading dot (for example <c>".pdf"</c> or <c>"pdf"</c>).</param>
    /// <param name="token">Cancels the operation before the file is read.</param>
    /// <returns>
    /// A result with <see cref="DocuTrustValidationResult.IsValid"/> set to <see langword="true"/> when the detected
    /// extension equals <paramref name="expectedExtension"/>. The detected MIME type and extension are filled in when
    /// the format is recognised.
    /// </returns>
    /// <exception cref="DocuTrust.Exceptions.DocuTrustValidationException">
    /// <paramref name="filePath"/> or <paramref name="expectedExtension"/> is null or empty, the file does not exist,
    /// the path is a directory, or the file cannot be read.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="token"/> was already cancelled.</exception>
    /// <remarks>
    /// <para><b>Security:</b> the path is trusted input. Never pass a path built from user input without first
    /// canonicalising it (<see cref="System.IO.Path.GetFullPath(string)"/>) and checking it stays inside your upload
    /// directory: DocuTrust does not prevent path traversal. Symbolic links are followed to their final target. On
    /// Windows a UNC path (<c>\\host\share</c>) makes the process authenticate to that host (NTLM credential leak).</para>
    /// <para>Targets that are empty or not regular files (FIFOs, character devices, most <c>/proc</c> entries) are
    /// rejected without being opened, because opening a FIFO blocks indefinitely.</para>
    /// <para>ZIP and OLE containers larger than 100 MB are rejected before inspection.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var result = await validator.ValidateFilePathAsync("/srv/uploads/3f2a.bin", ".pdf");
    /// if (!result.IsValid)
    ///     Console.WriteLine(result.Message);
    /// </code>
    /// </example>
    Task<DocuTrustValidationResult> ValidateFilePathAsync(string filePath, string expectedExtension , CancellationToken token = default );

    /// <summary>
    /// Checks that the content of <paramref name="fileStream"/> has the signature of <paramref name="expectedExtension"/>.
    /// </summary>
    /// <param name="fileStream">The stream to inspect. A seekable stream has its position restored afterwards.</param>
    /// <param name="expectedExtension">The extension the content should have, with or without the leading dot.</param>
    /// <param name="token">Cancels the operation before the stream is read.</param>
    /// <returns>
    /// A result with <see cref="DocuTrustValidationResult.IsValid"/> set to <see langword="true"/> when the detected
    /// extension equals <paramref name="expectedExtension"/>.
    /// </returns>
    /// <exception cref="DocuTrust.Exceptions.DocuTrustValidationException">
    /// <paramref name="fileStream"/> is null, <paramref name="expectedExtension"/> is null or empty, or the stream
    /// cannot be read.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="token"/> was already cancelled.</exception>
    /// <remarks>ZIP and OLE containers larger than 100 MB are rejected before inspection.</remarks>
    /// <example>
    /// <code>
    /// await using var stream = File.OpenRead(path);
    /// var result = await validator.ValidateFileStreamAsync(stream, ".docx");
    /// </code>
    /// </example>
    Task<DocuTrustValidationResult> ValidateFileStreamAsync(Stream fileStream, string expectedExtension , CancellationToken token = default);

    /// <summary>
    /// Detects the type of the file at <paramref name="filePath"/> from its signature, without comparing it to an
    /// expected type.
    /// </summary>
    /// <param name="filePath">Path to the file. It must come from your application, not from user input.</param>
    /// <param name="token">Cancels the operation before the file is read.</param>
    /// <returns>
    /// A result with <see cref="DocuTrustValidationResult.IsValid"/> set to <see langword="true"/> and the detected
    /// MIME type and extension when the format is recognised; otherwise <see cref="DocuTrustValidationResult.IsValid"/>
    /// is <see langword="false"/>.
    /// </returns>
    /// <exception cref="DocuTrust.Exceptions.DocuTrustValidationException">
    /// <paramref name="filePath"/> is null or empty, the file does not exist, the path is a directory, or the file
    /// cannot be read.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="token"/> was already cancelled.</exception>
    /// <remarks>
    /// <para><b>Security:</b> the path is trusted input. Never pass a path built from user input without first
    /// canonicalising it (<see cref="System.IO.Path.GetFullPath(string)"/>) and checking it stays inside your upload
    /// directory: DocuTrust does not prevent path traversal. Symbolic links are followed to their final target. On
    /// Windows a UNC path (<c>\\host\share</c>) makes the process authenticate to that host (NTLM credential leak).</para>
    /// <para>Targets that are empty or not regular files (FIFOs, character devices, most <c>/proc</c> entries) are
    /// rejected without being opened, because opening a FIFO blocks indefinitely.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var type = await validator.GetFileTypeAsync(path);
    /// Console.WriteLine(type.IsValid ? $"{type.ActualMimeType} (.{type.ActualExtension})" : "Unknown format");
    /// </code>
    /// </example>
    Task<DocuTrustValidationResult> GetFileTypeAsync(string filePath , CancellationToken token = default);

    /// <summary>
    /// Checks that an uploaded file has the signature of <paramref name="expectedExtension"/> and that its client file
    /// name does not claim a different type.
    /// </summary>
    /// <param name="file">The uploaded file, usually bound from an ASP.NET Core form.</param>
    /// <param name="expectedExtension">The extension the upload should have, with or without the leading dot. Required: an empty value fails validation.</param>
    /// <param name="token">Cancels the operation before the file is read.</param>
    /// <returns>
    /// A result with <see cref="DocuTrustValidationResult.IsValid"/> set to <see langword="true"/> when the magic
    /// bytes match <paramref name="expectedExtension"/> and the client file name either has the same extension (or an
    /// alias such as <c>jpg</c>/<c>jpeg</c>) or has no extension. Empty files and a missing expected extension return
    /// an invalid result.
    /// </returns>
    /// <exception cref="DocuTrust.Exceptions.DocuTrustValidationException"><paramref name="file"/> is null or its content cannot be read.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="token"/> was already cancelled.</exception>
    /// <remarks>
    /// Validation identifies the file type only: it does not scan content for macros or scripts. File names with
    /// control characters or <c>':'</c> are rejected. ZIP and OLE containers larger than 100 MB are rejected before
    /// inspection. Never store or serve an upload under the client-supplied name.
    /// </remarks>
    /// <example>
    /// <code>
    /// var result = await validator.ValidateFileAsync(file, ".pdf");
    /// if (!result.IsValid)
    ///     return Results.BadRequest(result.Message);
    /// </code>
    /// </example>
    Task<DocuTrustValidationResult> ValidateFileAsync(IFormFile file, string expectedExtension , CancellationToken token = default);
}
