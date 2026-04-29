using DocuTrust.Core.Services;
using DocuTrust.Core.Models;
using Microsoft.AspNetCore.Http;

// Minimal working example for Microsoft Office scanning
// This sample demonstrates how to detect macros and DDE in Word/Excel files.

var officeScanner = new DocuTrustOfficeScanner();

// Simulate an uploaded Word document
byte[] docContent = [/* binary content */]; 
var stream = new MemoryStream(docContent);
var file = new FormFile(stream, 0, docContent.Length, "file", "contract.docx");

// Perform a deep scan for VBA macros and suspicious links
DocuTrustFileCheckResult result = await officeScanner.ScanFileContentAsync(file);

if (!result.IsClean)
{
    Console.WriteLine($"Security Risk Detected: {result.Message}");
}
else
{
    Console.WriteLine("Office document is structurally safe.");
}