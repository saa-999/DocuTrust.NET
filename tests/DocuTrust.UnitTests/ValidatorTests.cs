using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for the public validator (DocuTrustFileScanner, DT-029..DT-034).</summary>
public class ValidatorTests
{
    internal static readonly byte[] Pdf = PdfTextExtractionTests.PdfWithText("validator");

    // Minimal PE-shaped bytes (MZ header with e_lfanew pointing at "PE\0\0"); benign, nothing executable.
    internal static byte[] PeLike()
    {
        var bytes = new byte[512];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        bytes[0x3C] = 0x80;
        "PE\0\0"u8.CopyTo(bytes.AsSpan(0x80));
        return bytes;
    }

    // DT-029: an empty expected extension accepted any detected format, executables included.
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    [InlineData(".")]
    public async Task ValidateFileAsync_WithoutExpectedExtension_FailsClosed(string? expected)
    {
        var result = await new DocuTrustFileScanner().ValidateFileAsync(TestFiles.FormFile(PeLike(), "tool.exe"), expected!);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task ValidateFileAsync_WithoutExpectedExtension_StillReportsDetectedType()
    {
        var result = await new DocuTrustFileScanner().ValidateFileAsync(TestFiles.FormFile(Pdf, "report.pdf"), "");

        Assert.False(result.IsValid);
        Assert.Equal("pdf", result.ActualExtension);
    }

    private static readonly byte[] Jpeg =
        [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9];

    // DT-030: only magic bytes were compared; the client file name could claim any other type.
    [Theory]
    [InlineData("invoice.html")]
    [InlineData("invoice.pdf.exe")]
    [InlineData("invoice.html.")]
    [InlineData("invoice.html .")]
    [InlineData("evil.asp:.pdf")]
    [InlineData("evil.html\0.pdf")]
    [InlineData("report\r\n.pdf")]
    public async Task ValidateFileAsync_ClientNameClaimsAnotherType_IsInvalid(string fileName)
    {
        var result = await new DocuTrustFileScanner().ValidateFileAsync(TestFiles.FormFile(Pdf, fileName), ".pdf");

        Assert.False(result.IsValid);
        Assert.Equal("pdf", result.ActualExtension);
    }

    [Theory]
    [InlineData("report.pdf")]
    [InlineData("REPORT.PDF")]
    [InlineData("invoice.exe.pdf")]
    [InlineData("blob")]
    [InlineData("C:\\Users\\someone\\report.pdf")]
    public async Task ValidateFileAsync_AcceptableClientName_IsValid(string fileName)
    {
        var result = await new DocuTrustFileScanner().ValidateFileAsync(TestFiles.FormFile(Pdf, fileName), ".pdf");

        Assert.True(result.IsValid, result.Message);
    }

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("photo.jpeg")]
    [InlineData("photo.JFIF")]
    public async Task ValidateFileAsync_ExtensionAlias_IsValid(string fileName)
    {
        var result = await new DocuTrustFileScanner().ValidateFileAsync(TestFiles.FormFile(Jpeg, fileName), ".jpg");

        Assert.True(result.IsValid, result.Message);
    }

    private const long OverLimit = 200L * 1024 * 1024;

    // DT-031: ZIP/OLE containers were handed to ZipArchive/OpenMcdf without any size limit.
    [Fact]
    public async Task ValidateFileStreamAsync_OversizedZipContainer_IsRejectedBeforeParsing()
    {
        var docx = OoxmlBuilder.Word().Build();
        using var stream = new TrickleStream(docx, reportedLength: OverLimit);

        var result = await new DocuTrustFileScanner().ValidateFileStreamAsync(stream, ".docx", default);

        Assert.False(result.IsValid);
        Assert.Contains("size limit", result.Message);
    }

    [Fact]
    public async Task ValidateFileAsync_OversizedOleContainer_IsRejectedBeforeParsing()
    {
        var doc = TestFiles.Cfb(4096);
        var file = new StreamFormFile(() => new MemoryStream(doc), OverLimit, "legacy.doc");

        var result = await new DocuTrustFileScanner().ValidateFileAsync(file, ".doc");

        Assert.False(result.IsValid);
        Assert.Contains("size limit", result.Message);
    }

    [Fact]
    public async Task ValidateFilePathAsync_OversizedZipContainer_IsRejectedBeforeParsing()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dt-{Guid.NewGuid():N}.docx");
        try
        {
            using (var fs = File.Create(path))
            {
                fs.Write(OoxmlBuilder.Word().Build());
                fs.SetLength(OverLimit); // sparse: no real disk usage
            }

            var result = await new DocuTrustFileScanner().ValidateFilePathAsync(path, ".docx");

            Assert.False(result.IsValid);
            Assert.Contains("size limit", result.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // Non-container formats only need their header and must keep validating at any size.
    [Fact]
    public async Task ValidateFileStreamAsync_LargeNonContainer_IsStillValidated()
    {
        using var stream = new TrickleStream(Pdf, reportedLength: OverLimit);

        var result = await new DocuTrustFileScanner().ValidateFileStreamAsync(stream, ".pdf", default);

        Assert.True(result.IsValid, result.Message);
    }

    // DT-032: the inspector seeks to 0 and left the caller's stream there.
    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(100)]
    public async Task ValidateFileStreamAsync_RestoresCallerPositionAndKeepsStreamOpen(int position)
    {
        using var stream = new MemoryStream(Pdf) { Position = position };

        var result = await new DocuTrustFileScanner().ValidateFileStreamAsync(stream, ".pdf", default);

        Assert.True(result.IsValid, result.Message);
        Assert.True(stream.CanRead);
        Assert.Equal(position, stream.Position);
    }
}
