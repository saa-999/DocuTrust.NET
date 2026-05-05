using Microsoft.AspNetCore.Http;
using DocuTrust.Core.Models;

namespace DocuTrust.Core.Abstractions;

internal interface IDocuTrustContentFile
{
    Task<DocuTrustFileCheckResult> GetPageAsync(int pageNumber, int allPages, IFormFile file, CancellationToken token = default);
    Task<DocuTrustFileCheckResult> ScanFileContentAsync(IFormFile file, CancellationToken token = default);
}
