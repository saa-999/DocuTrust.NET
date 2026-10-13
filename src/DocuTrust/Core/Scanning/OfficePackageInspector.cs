using System.Buffers;
using System.IO.Compression;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// First pass over an OOXML package: reads every part through a <see cref="BoundedReadStream"/> so the real
/// decompressed size, the shared budget and the compression ratio are enforced before any parser sees the package.
/// </summary>
internal sealed class OfficePackageInspector
{
    private static readonly HashSet<string> MaliciousExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".vbs", ".ps1", ".bat", ".com", ".scr", ".js", ".jse", ".wsf", ".wsh", ".vbe", ".jar"
    };

    private readonly ArrayPool<byte> _pool;
    private readonly OfficeScanLimits _limits;

    public OfficePackageInspector(ArrayPool<byte> pool, OfficeScanLimits limits)
    {
        _pool = pool;
        _limits = limits;
    }

    /// <summary>Returns a threat message, or <c>null</c> when the package passed. Requires a seekable stream.</summary>
    public async Task<string?> InspectAsync(Stream stream, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var preflight = ZipPreflight.Check(stream, _limits.MaxEntries, _pool, token);
        if (preflight != null)
            return preflight;

        var budget = new ScanBudget(_limits.MaxTotalUncompressedBytes);
        try
        {
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            if (zip.Entries.Count > _limits.MaxEntries)
                return "Package contains excessive number of parts.";

            foreach (var entry in zip.Entries)
            {
                token.ThrowIfCancellationRequested();

                if (entry.Length > _limits.MaxPartBytes)
                    return $"Part '{entry.FullName}' exceeds safety size limit.";

                if (entry.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                    return "VBA Macros detected in package.";

                if (entry.FullName.Contains("embeddings/"))
                {
                    string ext = Path.GetExtension(entry.FullName).ToLowerInvariant();
                    if (MaliciousExts.Contains(ext))
                        return $"Suspicious embedded executable found: {entry.FullName}";
                }

                await DrainAsync(entry, budget, token).ConfigureAwait(false);
            }
        }
        catch (ScanLimitExceededException ex)
        {
            return ex.Message;
        }
        catch (InvalidDataException)
        {
            return "Package contains a corrupt or unreadable part.";
        }

        return null;
    }

    private async Task DrainAsync(ZipArchiveEntry entry, ScanBudget budget, CancellationToken token)
    {
        await using var part = new BoundedReadStream(
            entry.Open(), _limits.MaxPartBytes, budget, entry.CompressedLength,
            _limits.MaxCompressionRatio, _limits.CompressionRatioThresholdBytes);

        await PooledChunkReader.ReadAsync(part, _pool, overlap: 0, long.MaxValue, static (_, _) => false, token)
            .ConfigureAwait(false);
    }
}
