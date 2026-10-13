using System.Reflection;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>
/// Guards against downgrades to dependency versions with known security defects.
/// The resolved runtime assemblies are checked, not the project files, so transitive pins are covered too.
/// </summary>
public class DependencyVersionTests
{
    // DT-035: OpenMcdf < 3.1.4 loops forever on cyclic CFB directories (CVE-2026-41511, CVE-2026-45785).
    // It is reached from IDocuTrustFileValidator through FileSignatures for every OLE/CFB upload.
    [Fact]
    public void OpenMcdf_ResolvedVersion_IncludesDirectoryCycleFixes()
    {
        var version = Assembly.Load("OpenMcdf").GetName().Version;

        Assert.NotNull(version);
        Assert.True(version >= new Version(3, 1, 4), $"OpenMcdf {version} is vulnerable; 3.1.4 or later is required.");
    }

    [Fact]
    public void FileSignatures_ResolvedVersion_DependsOnPatchedOpenMcdf()
    {
        var version = typeof(FileSignatures.FileFormatInspector).Assembly.GetName().Version;

        Assert.NotNull(version);
        Assert.True(version >= new Version(7, 3, 0), $"FileSignatures {version} pulls a vulnerable OpenMcdf; 7.3.0 or later is required.");
    }

    // DT-028: PdfPig 0.1.15/0.1.16 fix unbounded recursion (uncatchable stack overflow) in glyph,
    // colour-space and CMap parsing and add a nesting-depth guard.
    [Fact]
    public void PdfPig_ResolvedVersion_IncludesRecursionFixes()
    {
        var version = typeof(UglyToad.PdfPig.PdfDocument).Assembly.GetName().Version;

        Assert.NotNull(version);
        Assert.True(version >= new Version(0, 1, 16), $"PdfPig {version} has known infinite-recursion bugs; 0.1.16 or later is required.");
    }
}
