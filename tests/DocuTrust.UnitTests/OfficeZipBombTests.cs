using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using DocuTrust.Core.Scanning;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-009 (decompression bombs and package size limits).</summary>
public class OfficeZipBombTests
{
    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(byte[] package, OfficeScanLimits? limits = null)
        => new DocuTrustOfficeScanner(ArrayPool<byte>.Shared, limits ?? OfficeScanLimits.Default)
            .ScanFileContentAsync(TestFiles.FormFile(package, "upload.docx"));

    [Fact]
    public async Task ModernScan_HighlyCompressedPart_FailsClosed()
    {
        // 19 MB of zeros stays under the 20 MB part limit but compresses about 1000:1.
        var package = OoxmlBuilder.Word().Part("word/media/image1.png", new byte[19 * 1024 * 1024]).Build();

        var result = await Scan(package);

        Assert.False(result.IsClean);
        Assert.Contains("compression ratio", result.Message);
    }

    [Fact]
    public async Task ModernScan_TotalDecompressedBudgetExceeded_FailsClosed()
    {
        var random = new Random(42);
        var builder = OoxmlBuilder.Word();
        for (int i = 0; i < 3; i++)
        {
            var noise = new byte[400 * 1024];
            random.NextBytes(noise);
            builder.Part($"word/media/image{i}.png", noise);
        }

        var result = await Scan(builder.Build(), new OfficeScanLimits { MaxTotalUncompressedBytes = 1024 * 1024 });

        Assert.False(result.IsClean);
        Assert.Contains("budget", result.Message);
    }

    [Fact]
    public async Task ModernScan_TooManyEntries_FailsClosed()
    {
        var result = await Scan(ZipWithEntries(5001));

        Assert.False(result.IsClean);
        Assert.Contains("excessive number of parts", result.Message);
    }

    // ZipArchive materialises every central-directory record before comparing with the declared count.
    [Fact]
    public async Task ModernScan_CentralDirectoryLargerThanDeclared_FailsClosedWithoutThrowing()
    {
        var zip = ZipWithEntries(6000);
        int eocd = LastIndexOf(zip, 0x06054b50);
        BinaryPrimitives.WriteUInt16LittleEndian(zip.AsSpan(eocd + 8), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(zip.AsSpan(eocd + 10), 3);

        var result = await Scan(zip);

        Assert.False(result.IsClean);
        Assert.Contains("excessive number of parts", result.Message);
    }

    [Fact]
    public async Task TextExtraction_OversizedPart_FailsClosedBeforeDomLoad()
    {
        var body = $"<w:p><w:r><w:t>{new string('a', 21 * 1024 * 1024)}</w:t></w:r></w:p>";
        var package = OoxmlBuilder.Word(body).Build();

        var result = await new DocuTrustOfficeScanner().GetPageAsync(1, 1, TestFiles.FormFile(package, "big.docx"));

        Assert.False(result.IsClean);
        Assert.Null(result.Page);
    }

    [Fact]
    public async Task TextExtraction_HighlyCompressedPart_FailsClosed()
    {
        var body = $"<w:p><w:r><w:t>{new string('a', 5 * 1024 * 1024)}</w:t></w:r></w:p>";
        var package = OoxmlBuilder.Word(body).Build();

        var result = await new DocuTrustOfficeScanner().GetPageAsync(1, 1, TestFiles.FormFile(package, "bomb.docx"));

        Assert.False(result.IsClean);
        Assert.Contains("compression ratio", result.Message);
    }

    // The limits must not reject ordinary large documents.
    [Fact]
    public async Task ModernScan_LargeOrdinaryDocument_IsClean()
    {
        var random = new Random(7);
        var words = string.Join(' ', Enumerable.Range(0, 300_000).Select(_ => new string((char)('a' + random.Next(26)), 1 + random.Next(9))));
        var package = OoxmlBuilder.Word($"<w:p><w:r><w:t>{words}</w:t></w:r></w:p>").Build();

        var result = await Scan(package);

        Assert.True(result.IsClean, result.Message);
    }

    private static byte[] ZipWithEntries(int count)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            for (int i = 0; i < count; i++)
                zip.CreateEntry($"p{i}.xml", CompressionLevel.NoCompression);
        }
        return ms.ToArray();
    }

    private static int LastIndexOf(byte[] data, uint signature)
    {
        for (int i = data.Length - 4; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i)) == signature)
                return i;
        }
        throw new InvalidOperationException("signature not found");
    }
}
