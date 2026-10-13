using DocuTrust.Core.Constants;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression test for DT-037: size limits are 64-bit values with the documented magnitudes.</summary>
public class FileSizeTests
{
    [Fact]
    public void SizeLimits_HaveDocumentedValues()
    {
        Assert.Equal(104_857_600L, FileSize.MaxFileSizeBytes);
        Assert.Equal(157_286_400L, FileSize.MaxPdfSizeBytes);
        Assert.Equal(20_971_520L, FileSize.MaxPartSizeBytes);
        Assert.Equal(268_435_456L, FileSize.MaxTotalUncompressedBytes);
    }

    [Fact]
    public void ByteLimits_AreDeclaredAsLong()
    {
        var byteLimits = typeof(FileSize).GetFields()
            .Where(f => f.IsLiteral && (f.Name.EndsWith("Bytes", StringComparison.Ordinal) || f.Name.EndsWith("Size", StringComparison.Ordinal)));

        Assert.All(byteLimits, f =>
        {
            Assert.Equal(typeof(long), f.FieldType);
            Assert.True((long)f.GetRawConstantValue()! > 0, f.Name);
        });
    }
}
