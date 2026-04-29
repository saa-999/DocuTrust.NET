using Microsoft.AspNetCore.Http;
using DocuTrust.Core.Models;

namespace DocuTrust.Core.Abstractions;

/// <summary>
/// Internal contract for specialized scanners that dig into file content (like PDF or Office) to find malicious bits.
/// </summary>
internal interface IDocuTrustContentFile
{
    /// <summary>
    /// Pulls a specific page (or all of them) and checks if there's anything nasty inside.
    /// </summary>
    /// <param name="pageNumber">Page to grab. Use 0 for everything.</param>
    /// <param name="allPages">Total pages expected. 0 if we want it all.</param>
    /// <param name="file">The uploaded file to scan.</param>
    /// <returns>Result of the content check.</returns>
    Task<DocuTrustFileCheckResult> GetPageAsync(int pageNumber, int allPages, IFormFile file);

    /// <summary>
    /// Runs a deep scan on the whole file content looking for security red flags.
    /// </summary>
    /// <param name="file">The file to analyze.</param>
    /// <returns>A detailed check result.</returns>
    Task<DocuTrustFileCheckResult> ScanFileContentAsync(IFormFile file);
}
