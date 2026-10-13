using System.Buffers;
using DocuTrust.Core.Scanning;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-016: result messages must not echo entry names or exception text.</summary>
public class OfficeMessageSafetyTests
{
    private const string Marker = "INJECTED-MARKER";

    private static void AssertSafe(string? message)
    {
        Assert.NotNull(message);
        Assert.DoesNotContain(Marker, message);
        Assert.DoesNotContain(message!, char.IsControl);
    }

    [Fact]
    public async Task ModernScan_DangerousEntryNameWithLineBreaks_IsNotEchoed()
    {
        var package = OoxmlBuilder.Word().Part($"word/embeddings/a\r\n2026-10-13 INFO {Marker} scan ok.exe", TestFiles.Ascii("x")).Build();

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(package, "a.docx"));

        Assert.False(result.IsClean);
        AssertSafe(result.Message);
    }

    [Fact]
    public async Task ModernScan_OversizedEntryName_IsNotEchoed()
    {
        // Every other part is well under 4 KB; only the marker part exceeds the limit.
        var package = OoxmlBuilder.Word().Part($"word/media/{Marker}\r\nline.png", new byte[50_000]).Build();
        var scanner = new DocuTrustOfficeScanner(ArrayPool<byte>.Shared, new OfficeScanLimits { MaxPartBytes = 40_000 });

        var result = await scanner.ScanFileContentAsync(TestFiles.FormFile(package, "a.docx"));

        Assert.False(result.IsClean);
        AssertSafe(result.Message);
    }

    [Fact]
    public async Task ModernScan_StructuralFailure_DoesNotEchoExceptionText()
    {
        // Passes the first pass, but System.IO.Packaging rejects part names that differ only in case.
        var package = OoxmlBuilder.Word()
            .Part($"word/{Marker}.xml", "<x/>", "application/xml")
            .Part($"word/{Marker.ToLowerInvariant()}.xml", "<x/>", "application/xml")
            .Build();

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(package, "a.docx"));

        Assert.False(result.IsClean);
        AssertSafe(result.Message);
        Assert.DoesNotContain(Marker.ToLowerInvariant(), result.Message);
    }
}
