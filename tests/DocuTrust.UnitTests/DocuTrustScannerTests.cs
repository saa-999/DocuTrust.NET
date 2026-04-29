using Microsoft.AspNetCore.Http;
using Xunit;
using DocuTrust.Core.Services;
using DocuTrust.Core.Models;

namespace DocuTrust.Tests;

public class DocuTrustFileScannerTests
{
    private IFormFile CreateFormFile(byte[] content, string fileName)
    {
        var stream = new MemoryStream(content);
        return new FormFile(stream, 0, content.Length, "file", fileName);
    }

    [Fact]
    public async Task ValidateFileAsync_WithEmptyFile_ReturnsErrorMessage()
    {
        // Arrange
        var scanner = new DocuTrustFileScanner();
        var file = CreateFormFile(Array.Empty<byte>(), "empty.txt");

        // Act
        var result = await scanner.ValidateFileAsync(file, ".txt");

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("empty", result.Message);
    }

    [Fact]
    public async Task ValidateFileAsync_WithValidPdf_ReturnsTrue()
    {
        // Arrange
        var scanner = new DocuTrustFileScanner();
        // Use a more standard PDF header
        byte[] pdfBytes = "%PDF-1.7\n%\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Count 1/Kids[3 0 R]>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>/Contents 4 0 R>>\nendobj\n4 0 obj\n<</Length 21>>\nstream\nBT /F1 12 Tf 0 0 Td () Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000015 00000 n \n0000000060 00000 n \n0000000111 00000 n \n0000000212 00000 n \ntrailer\n<</Size 5/Root 1 0 R>>\nstartxref\n284\n%%EOF"u8.ToArray();
        var file = CreateFormFile(pdfBytes, "test.pdf");

        // Act
        var result = await scanner.ValidateFileAsync(file, ".pdf");

        // Assert
        Assert.True(result.IsValid, $"Result: {result.IsValid}, Message: {result.Message}, ActualExt: {result.ActualExtension}");
        Assert.Contains("successful", result.Message);
    }
}
