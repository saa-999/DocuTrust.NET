using System.Text;
using Microsoft.AspNetCore.Http;
using Xunit;
using DocuTrust.Core.Services;
using DocuTrust.Core.Models;
using UglyToad.PdfPig.Writer;
using UglyToad.PdfPig.Content;

namespace DocuTrust.Tests;

public class DocuTrustPdfScannerTests
{
    private IFormFile CreateFormFile(byte[] content, string fileName)
    {
        var stream = new MemoryStream(content);
        return new FormFile(stream, 0, content.Length, "file", fileName);
    }

    [Fact]
    public async Task ScanFileContentAsync_DetectsJavaScriptInOpenAction()
    {
        // Arrange
        var scanner = new DocuTrustPdfScanner();
        byte[] pdfBytes = CreatePdfWithOpenActionJavaScript();
        var file = CreateFormFile(pdfBytes, "malicious.pdf");

        // Act
        var result = await scanner.ScanFileContentAsync(file);

        // Assert
        Assert.False(result.IsClean);
        Assert.Contains("JavaScript", result.Message);
    }

    [Fact]
    public async Task ScanFileContentAsync_ReturnsIsCleanTrueForCleanPdf()
    {
        // Arrange
        var scanner = new DocuTrustPdfScanner();
        byte[] pdfBytes = CreateCleanPdf();
        var file = CreateFormFile(pdfBytes, "clean.pdf");

        // Act
        var result = await scanner.ScanFileContentAsync(file);

        // Assert
        Assert.True(result.IsClean);
        Assert.Equal("The PDF file passed behavioral analysis.", result.Message);
    }

    // DT-007: the "%PDF-" header was read with one ReadAsync; a short read rejected valid files.
    [Fact]
    public async Task ScanFileContentAsync_HeaderDeliveredInSmallReads_IsRecognised()
    {
        var scanner = new DocuTrustPdfScanner();
        byte[] pdfBytes = CreateCleanPdf();
        var file = new DocuTrust.Tests.TestSupport.StreamFormFile(
            () => new DocuTrust.Tests.TestSupport.TrickleStream(pdfBytes, maxChunk: 2), pdfBytes.Length, "clean.pdf");

        var result = await scanner.ScanFileContentAsync(file);

        Assert.True(result.IsClean, result.Message);
    }

    // DT-018: the header check rewound the stream with Position = 0, which throws on non-seekable streams.
    [Fact]
    public async Task ScanFileContentAsync_NonSeekableStream_ReturnsVerdict()
    {
        var scanner = new DocuTrustPdfScanner();
        byte[] pdfBytes = CreatePdfWithOpenActionJavaScript();
        var file = new DocuTrust.Tests.TestSupport.StreamFormFile(
            () => new DocuTrust.Tests.TestSupport.TrickleStream(pdfBytes, seekable: false), pdfBytes.Length, "malicious.pdf");

        var result = await scanner.ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.Contains("JavaScript", result.Message);
    }

    private byte[] CreateCleanPdf()
    {
        var builder = new PdfDocumentBuilder();
        builder.AddPage(PageSize.A4);
        return builder.Build();
    }

    private byte[] CreatePdfWithOpenActionJavaScript()
    {
        string pdfContent = @"%PDF-1.1
1 0 obj
<</Type /Catalog /Pages 2 0 R /OpenAction 3 0 R>>
endobj
2 0 obj
<</Type /Pages /Count 1 /Kids [4 0 R]>>
endobj
3 0 obj
<</S /JavaScript /JS (app.alert('XSS');)>>
endobj
4 0 obj
<</Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 5 0 R>>
endobj
5 0 obj
<</Length 1>>
stream
 
endstream
endobj
trailer
<</Root 1 0 R /Size 6>>
%%EOF";
        return Encoding.ASCII.GetBytes(pdfContent);
    }
}
