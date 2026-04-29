using DocuTrust.Core.Services;
using DocuTrust.Core.Models;
using DocuTrust.Core.Abstractions;
using Microsoft.AspNetCore.Http;

// Minimal working example for general file validation
// This demonstrates the primary IDocuTrustFileValidator API.

IDocuTrustFileValidator validator = new DocuTrustFileScanner();

// Simulate an uploaded file
byte[] content = [/* file bytes */];
var stream = new MemoryStream(content);
var file = new FormFile(stream, 0, content.Length, "file", "report.pdf");

// Validate that the file content actually matches a PDF signature
// This prevents users from uploading "malware.exe" renamed to "malware.pdf"
DocuTrustValidationResult result = await validator.ValidateFileAsync(file, ".pdf");

if (result.IsValid)
{
    Console.WriteLine($"Validation Passed: Detected {result.ActualMimeType}");
}
else
{
    Console.WriteLine($"Validation Failed: {result.Message}");
}