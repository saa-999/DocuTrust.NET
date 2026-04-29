using System;

namespace DocuTrust.Exceptions;

/// <summary>
/// Custom exception for file security and validation errors.
/// </summary>
public class DocuTrustValidationException : Exception
{
    /// <summary>
    /// Creates a new validation exception with a specific message.
    /// </summary>
    public DocuTrustValidationException(string message) : base(message) { }

    /// <summary>
    /// Creates a new validation exception with a message and the original error.
    /// </summary>
    public DocuTrustValidationException(string message, Exception innerException) : base(message, innerException) { }
}
