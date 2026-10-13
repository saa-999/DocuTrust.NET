using System.Buffers.Binary;
using DocuTrust.Core.Services;
using DocuTrust.Tests.TestSupport;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-015 (encrypted Office documents must not be reported clean).</summary>
public class OfficeEncryptionTests
{
    private static Task<Core.Models.DocuTrustFileCheckResult> Scan(byte[] content, string name)
        => new DocuTrustOfficeScanner().ScanFileContentAsync(TestFiles.FormFile(content, name));

    private static byte[] Filler(int size, byte seed = 0x2E)
    {
        var data = new byte[size];
        for (int i = 0; i < size; i++)
            data[i] = (byte)(seed + i % 7);
        return data;
    }

    private static byte[] WordStream(bool encrypted)
    {
        var fib = Filler(6000);
        BinaryPrimitives.WriteUInt16LittleEndian(fib, 0xA5EC);           // wIdent
        BinaryPrimitives.WriteUInt16LittleEndian(fib.AsSpan(10), (ushort)(encrypted ? 0x0100 : 0x0000)); // fEncrypted
        return fib;
    }

    private static byte[] WorkbookStream(bool encrypted)
    {
        var book = Filler(6000);
        BinaryPrimitives.WriteUInt16LittleEndian(book, 0x0809);            // BOF
        BinaryPrimitives.WriteUInt16LittleEndian(book.AsSpan(2), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(book.AsSpan(20), (ushort)(encrypted ? 0x002F : 0x0042)); // FILEPASS vs CODEPAGE
        BinaryPrimitives.WriteUInt16LittleEndian(book.AsSpan(22), 4);
        return book;
    }

    private static byte[] CurrentUserStream(bool encrypted)
    {
        var atom = Filler(40);
        BinaryPrimitives.WriteUInt32LittleEndian(atom.AsSpan(8), 0x14);
        BinaryPrimitives.WriteUInt32LittleEndian(atom.AsSpan(12), encrypted ? 0xE391C05F : 0xF3D1C4DF);
        return atom;
    }

    [Fact]
    public async Task LegacyScan_PasswordProtectedOoxml_FailsClosedAsEncrypted()
    {
        var cfb = new CfbBuilder()
            .Stream("EncryptionInfo", Filler(200))
            .Stream("EncryptedPackage", Filler(9000, 0x41))
            .Build();

        var result = await Scan(cfb, "protected.docx");

        Assert.False(result.IsClean);
        Assert.True(result.IsEncrypted);
    }

    [Fact]
    public async Task LegacyScan_PasswordProtectedOoxmlOnNonSeekableStream_FailsClosedAsEncrypted()
    {
        var cfb = new CfbBuilder()
            .Stream("EncryptionInfo", Filler(200))
            .Stream("EncryptedPackage", Filler(9000, 0x41))
            .Build();
        var file = new StreamFormFile(() => new TrickleStream(cfb, seekable: false), cfb.Length, "protected.xlsx");

        var result = await new DocuTrustOfficeScanner().ScanFileContentAsync(file);

        Assert.False(result.IsClean);
        Assert.True(result.IsEncrypted);
    }

    [Theory]
    [InlineData("doc")]
    [InlineData("xls")]
    [InlineData("ppt")]
    public async Task LegacyScan_EncryptedBinaryDocument_FailsClosedAsEncrypted(string kind)
    {
        var result = await Scan(Legacy(kind, encrypted: true), "legacy." + kind);

        Assert.False(result.IsClean);
        Assert.True(result.IsEncrypted);
    }

    [Theory]
    [InlineData("doc")]
    [InlineData("xls")]
    [InlineData("ppt")]
    public async Task LegacyScan_UnencryptedBinaryDocument_IsClean(string kind)
    {
        var result = await Scan(Legacy(kind, encrypted: false), "legacy." + kind);

        Assert.True(result.IsClean, result.Message);
        Assert.False(result.IsEncrypted);
    }

    [Fact]
    public async Task ModernScan_EmbeddedPasswordProtectedDocument_FailsClosed()
    {
        var inner = new CfbBuilder().Stream("EncryptionInfo", Filler(200)).Stream("EncryptedPackage", Filler(9000, 0x41)).Build();

        var result = await Scan(OoxmlBuilder.Word().Part("word/embeddings/oleObject1.bin", inner).Build(), "upload.docx");

        Assert.False(result.IsClean);
        Assert.Contains("encrypted", result.Message);
    }

    private static byte[] Legacy(string kind, bool encrypted) => kind switch
    {
        "doc" => new CfbBuilder().Stream("WordDocument", WordStream(encrypted)).Stream("1Table", Filler(5000)).Build(),
        "xls" => new CfbBuilder().Stream("Workbook", WorkbookStream(encrypted)).Build(),
        _ => new CfbBuilder().Stream("Current User", CurrentUserStream(encrypted)).Stream("PowerPoint Document", Filler(5000)).Build(),
    };
}
