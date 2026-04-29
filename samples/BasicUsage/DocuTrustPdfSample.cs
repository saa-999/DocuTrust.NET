using DocuTrust.Core.Services;
using DocuTrust.Core.Models;
using Microsoft.AspNetCore.Http;
using System.Text;

// Minimal working example for PDF scanning
// This sample demonstrates how to use the DocuTrustPdfScanner directly.

var pdfScanner = new DocuTrustPdfScanner();

// Simulate an uploaded file
var content = "%PDF-1.7..."u8.ToArray();
var stream = new MemoryStream(content);
var file = new FormFile(stream, 0, content.Length, "file", "test.pdf");

// 1. Perform a deep behavioral scan
// This looks for JavaScript, Launch commands, and other hidden threats.
DocuTrustFileCheckResult scanResult = await pdfScanner.ScanFileContentAsync(file);

if (!scanResult.IsClean)
{
    Console.WriteLine($"Alert! {scanResult.Message}");
}
else
{
    Console.WriteLine("PDF is clean based on behavioral analysis.");
}

// 2. Extract text from the first page
DocuTrustFileCheckResult extractResult = await pdfScanner.GetPageAsync(1, 1, file);
Console.WriteLine($"Extracted Text: {extractResult.Page}");