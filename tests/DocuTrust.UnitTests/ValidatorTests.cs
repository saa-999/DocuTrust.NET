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
}
