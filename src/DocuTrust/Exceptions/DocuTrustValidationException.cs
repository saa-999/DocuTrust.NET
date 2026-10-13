using System;

namespace DocuTrust.Exceptions;

/// <summary>
/// Thrown by <see cref="DocuTrust.Core.Abstractions.IDocuTrustFileValidator"/> when the input is invalid (a null or
/// empty argument, a missing file, a directory) or the file cannot be read.
/// </summary>
/// <remarks>
/// A file of the wrong type does not throw; it returns a result whose
/// <see cref="DocuTrust.Core.Models.DocuTrustValidationResult.IsValid"/> is <see langword="false"/>. The message is
/// a fixed string that does not include the path. The original error, when there is one, is in
/// <see cref="Exception.InnerException"/>; log it, but do not return it to clients.
/// </remarks>
/// <example>
/// <code>
/// try
/// {
///     var result = await validator.ValidateFilePathAsync(path, ".pdf");
/// }
/// catch (DocuTrustValidationException ex)
/// {
///     logger.LogWarning(ex.InnerException, "Validation could not run: {Message}", ex.Message);
/// }
/// </code>
/// </example>
public class DocuTrustValidationException : Exception
{
    /// <summary>
    /// Creates an exception with the given message.
    /// </summary>
    /// <param name="message">A description of the error.</param>
    public DocuTrustValidationException(string message) : base(message) { }

    /// <summary>
    /// Creates an exception with the given message and the exception that caused it.
    /// </summary>
    /// <param name="message">A description of the error.</param>
    /// <param name="innerException">The exception that caused this one.</param>
    public DocuTrustValidationException(string message, Exception innerException) : base(message, innerException) { }
}
