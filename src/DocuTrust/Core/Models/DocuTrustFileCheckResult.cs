namespace DocuTrust.Core.Models;

/// <summary>
/// Holds the details of a deep content scan, like whether it's clean or encrypted.
/// </summary>
public class DocuTrustFileCheckResult
{
    /// <summary>
    /// True if no malicious bits were found.
    /// </summary>
    public bool IsClean { get; set; }

    /// <summary>
    /// True if the file is locked with a password.
    /// </summary>
    public bool IsEncrypted { get; set; }

    /// <summary>
    /// True if we actually managed to scan the file.
    /// </summary>
    public bool IsScanned { get; set; }

    /// <summary>
    /// Details on the encryption rights of the file.
    /// </summary>
    public bool EncryptionPermissions { get; set; }

    /// <summary>
    /// The text we managed to pull out of the page.
    /// </summary>
    public string? Page { get; set; }

    /// <summary>
    /// A human-friendly message about what happened during the check.
    /// </summary>
    public string? Message { get; set; }
}
