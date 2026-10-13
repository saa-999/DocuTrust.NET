using System.Diagnostics;
using DocuTrust.Core.Models;
using DocuTrust.Core.Services;
using DocuTrust.Exceptions;
using Xunit;

namespace DocuTrust.Tests;

/// <summary>Regression tests for DT-034 (path-based validation: FIFOs, non-regular files, symlinks).</summary>
public sealed class ValidatorPathTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("docutrust-");

    public void Dispose() => _dir.Delete(recursive: true);

    private static bool SupportsFifo => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private string MakeFifo(string name)
    {
        var path = Path.Combine(_dir.FullName, name);
        using var process = Process.Start(new ProcessStartInfo("mkfifo", [path]) { UseShellExecute = false })!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        return path;
    }

    private static async Task<DocuTrustValidationResult> CallWithoutHanging(string fifoPath, Func<Task<DocuTrustValidationResult>> call)
    {
        var task = Task.Run(call);
        bool finished = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))) == task;
        if (!finished)
        {
            // Release the reader stuck in open(2) so no thread stays blocked, then report the hang.
            using (new FileStream(fifoPath, FileMode.Open, FileAccess.Write)) { }
            await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
        }
        Assert.True(finished, "validation blocked on a FIFO");
        return await task;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PathValidation_Fifo_ReturnsWithoutBlocking(bool getFileType)
    {
        if (!SupportsFifo)
            return; // FIFOs are a Unix concept; nothing to verify on Windows.

        var fifo = MakeFifo("upload.pdf");
        var scanner = new DocuTrustFileScanner();

        var result = await CallWithoutHanging(fifo, () => getFileType
            ? scanner.GetFileTypeAsync(fifo)
            : scanner.ValidateFilePathAsync(fifo, ".pdf"));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task PathValidation_SymlinkToFifo_ReturnsWithoutBlocking()
    {
        if (!SupportsFifo)
            return;

        var fifo = MakeFifo("pipe");
        var link = Path.Combine(_dir.FullName, "upload.pdf");
        File.CreateSymbolicLink(link, fifo);

        var result = await CallWithoutHanging(fifo, () => new DocuTrustFileScanner().ValidateFilePathAsync(link, ".pdf"));

        Assert.False(result.IsValid);
    }

    // No false positives: a symlink to a regular file is validated against its target.
    [Fact]
    public async Task PathValidation_SymlinkToRegularFile_IsValidated()
    {
        var target = Path.Combine(_dir.FullName, "real.pdf");
        File.WriteAllBytes(target, ValidatorTests.Pdf);
        var link = Path.Combine(_dir.FullName, "link.pdf");
        File.CreateSymbolicLink(link, target);

        var result = await new DocuTrustFileScanner().ValidateFilePathAsync(link, ".pdf");

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task PathValidation_EmptyFile_IsInvalid()
    {
        var path = Path.Combine(_dir.FullName, "empty.pdf");
        File.WriteAllBytes(path, []);

        var result = await new DocuTrustFileScanner().ValidateFilePathAsync(path, ".pdf");

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task PathValidation_Directory_Throws()
    {
        await Assert.ThrowsAsync<DocuTrustValidationException>(
            () => new DocuTrustFileScanner().ValidateFilePathAsync(_dir.FullName, ".pdf"));
    }
}
