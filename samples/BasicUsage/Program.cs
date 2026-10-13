using System.Text;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Models;
using DocuTrust.Exceptions;
using DocuTrust.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

// Sample bytes. Real code gets these from an upload, a blob store or the disk.
byte[] pdfBytes = Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
byte[] pngBytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52];

// Step 1: register DocuTrust and resolve the validator.
// In ASP.NET Core you call builder.Services.AddDocuTrust() and inject IDocuTrustFileValidator instead.
var services = new ServiceCollection();
services.AddDocuTrust();
using var provider = services.BuildServiceProvider();
using var scope = provider.CreateScope();
var validator = scope.ServiceProvider.GetRequiredService<IDocuTrustFileValidator>();

// Step 2: validate an upload whose bytes and name both say PDF. This passes.
IFormFile upload = ToFormFile(pdfBytes, "report.pdf");
Print("2. Real PDF upload", await validator.ValidateFileAsync(upload, ".pdf"));

// Step 3: a PNG renamed to report.pdf. The magic bytes say PNG, so this fails.
IFormFile renamed = ToFormFile(pngBytes, "report.pdf");
Print("3. PNG renamed to .pdf", await validator.ValidateFileAsync(renamed, ".pdf"));

// Step 4: PDF bytes sent under an executable name. The client file name must match the expected type too.
IFormFile badName = ToFormFile(pdfBytes, "invoice.exe");
Print("4. PDF bytes named .exe", await validator.ValidateFileAsync(badName, ".pdf"));

// Step 5: no expected extension. ValidateFileAsync fails closed and still reports what it detected.
Print("5. Empty expected extension", await validator.ValidateFileAsync(ToFormFile(pdfBytes, "report.pdf"), ""));

// Step 6: validate a stream. The stream position is restored afterwards, so you can keep reading it.
using (var stream = new MemoryStream(pdfBytes))
{
    stream.Position = 4;
    Print("6. Stream", await validator.ValidateFileStreamAsync(stream, ".pdf"));
    Console.WriteLine($"   Stream position after validation: {stream.Position}");
}

// Step 7: validate a file on disk, then detect its type without an expected extension.
// Only pass paths your application controls. DocuTrust does not prevent path traversal.
string tempPath = Path.Combine(Path.GetTempPath(), $"docutrust-sample-{Guid.NewGuid():N}.pdf");
await File.WriteAllBytesAsync(tempPath, pdfBytes);
try
{
    Print("7a. File path", await validator.ValidateFilePathAsync(tempPath, ".pdf"));
    Print("7b. Detected type", await validator.GetFileTypeAsync(tempPath));
}
finally
{
    File.Delete(tempPath);
}

// Step 8: handle errors. Bad input (null, empty, missing file) throws DocuTrustValidationException.
// A file that is merely the wrong type does not throw; check IsValid instead.
try
{
    await validator.ValidateFilePathAsync(tempPath, ".pdf");
}
catch (DocuTrustValidationException ex)
{
    Console.WriteLine($"8. Missing file -> {nameof(DocuTrustValidationException)}: {ex.Message}");
}

static IFormFile ToFormFile(byte[] content, string fileName)
    => new FormFile(new MemoryStream(content), 0, content.Length, "file", fileName);

static void Print(string label, DocuTrustValidationResult result)
{
    Console.WriteLine($"{label} -> IsValid={result.IsValid}, Type={result.ActualMimeType ?? "unknown"} ({result.ActualExtension ?? "-"})");
    Console.WriteLine($"   {result.Message}");
}
