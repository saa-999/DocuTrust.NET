using System.Buffers;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Http;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Models;
using DocuTrust.Core.Constants;
using DocuTrust.Core.Scanning;
using DocuTrust.Exceptions;


namespace DocuTrust.Core.Services;

internal class DocuTrustOfficeScanner : IDocuTrustContentFile
{
    private const string OleNativeStreamName = "\u0001Ole10Native";

    // Password-protected OOXML is a CFB holding these two streams; the content itself is ciphertext.
    private const string EncryptedPackageStreamName = "EncryptedPackage";
    private const string EncryptionInfoStreamName = "EncryptionInfo";

    private static readonly KeywordSet LegacyIndicators = new(
    [
        "VBAProject", "_VBA_PROJECT_CUR", "PROJECTwm",
        "AutoOpen", "AutoExec", "Document_Open", "Workbook_Open",
        "Execute", "Shell", "CreateObject", "WScript.Shell", "powershell.exe",
        OleNativeStreamName,
        EncryptedPackageStreamName, EncryptionInfoStreamName
    ]);

    private static ReadOnlySpan<byte> CfbMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private readonly ArrayPool<byte> _bufferPool;
    private readonly OfficeScanLimits _limits;

    public DocuTrustOfficeScanner() : this(ArrayPool<byte>.Shared, OfficeScanLimits.Default)
    {
    }

    internal DocuTrustOfficeScanner(ArrayPool<byte> bufferPool) : this(bufferPool, OfficeScanLimits.Default)
    {
    }

    internal DocuTrustOfficeScanner(ArrayPool<byte> bufferPool, OfficeScanLimits limits)
    {
        _bufferPool = bufferPool;
        _limits = limits;
    }

    /// <summary>
    /// Extracts text. The full security scan runs first: a document that is not clean is returned as the scan
    /// verdict (no text), so <c>IsClean = true</c> here always means "scanned and clean".
    /// </summary>
    public async Task<DocuTrustFileCheckResult> GetPageAsync(int pageNumber, int allPages, IFormFile file, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            return await ScanTimeLimit.RunAsync(_limits.ScanTimeout, token, async budget =>
            {
                var (scan, container, kind) = await ScanCoreAsync(file, budget);
                if (!scan.IsClean)
                    return scan;

                if (container == OfficeContainer.Package)
                    return ExtractModernText(file, kind, budget);

                using var stream = file.OpenReadStream();
                return await ExtractLegacyTextAsync(stream, budget);
            });
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Failed to extract content from Office document.", ex);
        }
    }

    public async Task<DocuTrustFileCheckResult> ScanFileContentAsync(IFormFile file, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            return await ScanTimeLimit.RunAsync(_limits.ScanTimeout, token,
                async budget => (await ScanCoreAsync(file, budget)).Result);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Deep scan of Office document failed.", ex);
        }
    }

    private async Task<(DocuTrustFileCheckResult Result, OfficeContainer Container, OfficeDocumentKind Kind)> ScanCoreAsync(IFormFile file, CancellationToken token)
    {
        if (file.Length > FileSize.MaxFileSizeBytes)
            return (Fail("File exceeds security scan size limit."), OfficeContainer.Unsupported, OfficeDocumentKind.Unknown);

        // Every pass opens a fresh stream from the IFormFile: no Position resets, works for non-seekable streams.
        byte[] header = await ReadHeaderAsync(file, 8, token);

        if (header.AsSpan().SequenceEqual(CfbMagic))
        {
            // Encryption flags of .doc/.xls/.ppt and encrypted OOXML need random access to the CFB structure.
            using (var cfb = file.OpenReadStream())
            {
                if (CompoundFileInspector.Inspect(cfb) == CompoundFileVerdict.Encrypted)
                    return (EncryptedResult(), OfficeContainer.Compound, OfficeDocumentKind.Unknown);
            }

            using var stream = file.OpenReadStream();
            return (await ScanLegacyOfficeAsync(stream, token), OfficeContainer.Compound, OfficeDocumentKind.Unknown);
        }

        if (header.Length >= 4 && header[0] == 0x50 && header[1] == 0x4B && (header[2] == 0x03 || header[2] == 0x01))
        {
            var (result, kind) = await ScanModernOfficeAsync(file, token);
            return (result, OfficeContainer.Package, kind);
        }

        return (Fail("Unsupported or malformed Office format."), OfficeContainer.Unsupported, OfficeDocumentKind.Unknown);
    }

    private static DocuTrustFileCheckResult Fail(string message) => new() { IsClean = false, Message = message, IsScanned = true };

    private static DocuTrustFileCheckResult EncryptedResult() => new()
    {
        IsClean = false,
        IsEncrypted = true,
        IsScanned = false,
        Message = "Encrypted (password-protected) Office document: content cannot be scanned.",
    };

    private static async Task<byte[]> ReadHeaderAsync(IFormFile file, int count, CancellationToken token)
    {
        using var stream = file.OpenReadStream();
        var header = new byte[count];
        int read = await stream.ReadAtLeastAsync(header, count, throwOnEndOfStream: false, token);
        return read == count ? header : header[..read];
    }

    private async Task<(DocuTrustFileCheckResult Result, OfficeDocumentKind Kind)> ScanModernOfficeAsync(IFormFile file, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        OfficePackageVerdict verdict;
        using (var stream = file.OpenReadStream())
        {
            // ZipArchive needs random access to the central directory; fail closed instead of throwing.
            if (!stream.CanSeek)
                return (new DocuTrustFileCheckResult { IsClean = false, Message = "Office package scanning requires a seekable stream.", IsScanned = false }, OfficeDocumentKind.Unknown);

            verdict = await new OfficePackageInspector(_bufferPool, _limits).InspectAsync(stream, token);
        }

        if (verdict.Threat != null)
            return (Fail(verdict.Threat), verdict.Kind);

        try
        {
            // The first pass already checked every part's content types, relationships, field codes and embedded
            // payloads. Opening exactly the declared SDK type confirms the package parses as that type.
            using var stream = file.OpenReadStream();
            using OpenXmlPackage document = verdict.Kind switch
            {
                OfficeDocumentKind.Word => WordprocessingDocument.Open(stream, false, OpenSettings()),
                OfficeDocumentKind.Excel => SpreadsheetDocument.Open(stream, false, OpenSettings()),
                OfficeDocumentKind.PowerPoint => PresentationDocument.Open(stream, false, OpenSettings()),
                _ => throw new InvalidDataException(),
            };
            token.ThrowIfCancellationRequested();

            var message = verdict.Kind switch
            {
                OfficeDocumentKind.Word => "Word document is clean.",
                OfficeDocumentKind.Excel => "Excel document is clean.",
                _ => "PowerPoint document is clean.",
            };
            return (new DocuTrustFileCheckResult { IsClean = true, Message = message, IsScanned = true }, verdict.Kind);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // Exception text (part URIs, parser internals) is never copied into the result.
            return (Fail("Structural deep scan failed: the package is not a valid document of its declared type."), verdict.Kind);
        }
    }

    private static OpenSettings OpenSettings() => new()
    {
        AutoSave = false,
        MarkupCompatibilityProcessSettings = new MarkupCompatibilityProcessSettings(
            MarkupCompatibilityProcessMode.NoProcess,
            FileFormatVersions.Microsoft365),
    };

    private async Task<DocuTrustFileCheckResult> ScanLegacyOfficeAsync(Stream stream, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        // Stream the file through one pooled 64 KB window instead of loading and decoding it whole.
        // The window keeps (longest pattern - 1) bytes of overlap and matches ASCII plus UTF-16LE at any offset.
        string? indicator = null;
        var read = await PooledChunkReader.ReadAsync(
            stream,
            _bufferPool,
            LegacyIndicators.MaxPatternLength - 1,
            FileSize.MaxFileSizeBytes,
            (window, _) => (indicator = LegacyIndicators.FindFirst(window)) != null,
            token).ConfigureAwait(false);

        if (read.LimitExceeded)
            return Fail("File exceeds security scan size limit.");

        if (indicator is EncryptedPackageStreamName or EncryptionInfoStreamName)
            return EncryptedResult();

        if (indicator == OleNativeStreamName)
            return Fail("Legacy file contains embedded OLE objects.");

        if (indicator != null)
            return Fail($"Legacy malicious indicator detected: '{indicator}'.");

        return new DocuTrustFileCheckResult { IsClean = true, Message = "Legacy heuristics passed.", IsScanned = true };
    }

    /// <summary>
    /// Streams the text nodes of the body parts (no DOM) with a character cap. Any parse error fails closed.
    /// </summary>
    private DocuTrustFileCheckResult ExtractModernText(IFormFile file, OfficeDocumentKind kind, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var text = new StringBuilder();
        try
        {
            using var stream = file.OpenReadStream();
            switch (kind)
            {
                case OfficeDocumentKind.Word:
                {
                    using var doc = WordprocessingDocument.Open(stream, false, OpenSettings());
                    if (doc.MainDocumentPart is { } main && !AppendText(main, text, token))
                        return TextLimitExceeded();
                    break;
                }
                case OfficeDocumentKind.Excel:
                {
                    using var doc = SpreadsheetDocument.Open(stream, false, OpenSettings());
                    var workbook = doc.WorkbookPart;
                    foreach (var sheetId in ReadRelationshipIds(workbook, "sheet", token))
                    {
                        // Chartsheets and dialog sheets have no cell text; skip them instead of failing.
                        if (workbook!.GetPartById(sheetId) is WorksheetPart sheet && !AppendText(sheet, text, token))
                            return TextLimitExceeded();
                    }
                    break;
                }
                case OfficeDocumentKind.PowerPoint:
                {
                    using var doc = PresentationDocument.Open(stream, false, OpenSettings());
                    var presentation = doc.PresentationPart;
                    foreach (var slideId in ReadRelationshipIds(presentation, "sldId", token))
                    {
                        if (presentation!.GetPartById(slideId) is SlidePart slide && !AppendText(slide, text, token))
                            return TextLimitExceeded();
                    }
                    break;
                }
                default:
                    return Fail("Text extraction failed: the document could not be parsed.");
            }

            return new DocuTrustFileCheckResult { IsClean = true, Page = text.ToString(), Message = "Text extracted from OpenXML format.", IsScanned = true };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return Fail("Text extraction failed: the document could not be parsed.");
        }
    }

    /// <summary>Reads the <c>r:id</c> of each <paramref name="elementName"/> in a main part, in document order.</summary>
    private static List<string> ReadRelationshipIds(OpenXmlPart? part, string elementName, CancellationToken token)
    {
        var ids = new List<string>();
        if (part == null)
            return ids;

        using var partStream = part.GetStream(FileMode.Open, FileAccess.Read);
        using var reader = SafeXml.Create(partStream);
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            if (reader.NodeType != XmlNodeType.Element || reader.LocalName != elementName)
                continue;
            for (bool more = reader.MoveToFirstAttribute(); more; more = reader.MoveToNextAttribute())
            {
                if (reader.LocalName == "id" && reader.NamespaceURI.EndsWith("/relationships", StringComparison.Ordinal))
                    ids.Add(reader.Value);
            }
            reader.MoveToElement();
        }
        return ids;
    }

    /// <summary>Appends every text node of the part. Returns false when the extraction cap is exceeded.</summary>
    private bool AppendText(OpenXmlPart part, StringBuilder text, CancellationToken token)
    {
        using var partStream = part.GetStream(FileMode.Open, FileAccess.Read);
        using var reader = SafeXml.Create(partStream);
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
            {
                text.Append(reader.Value);
                if (text.Length > _limits.MaxExtractedTextChars)
                    return false;
            }
        }
        return true;
    }

    private static DocuTrustFileCheckResult TextLimitExceeded()
        => Fail("Extracted text exceeds the safety size limit.");

    private async Task<DocuTrustFileCheckResult> ExtractLegacyTextAsync(Stream stream, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var sb = new StringBuilder();
        bool tooLong = false;
        var read = await PooledChunkReader.ReadAsync(
            stream,
            _bufferPool,
            overlap: 0,
            FileSize.MaxFileSizeBytes,
            (window, _) =>
            {
                foreach (byte b in window)
                {
                    // Same mapping as Encoding.ASCII: bytes above 0x7F become '?'.
                    char c = b < 0x80 ? (char)b : '?';
                    if (char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsWhiteSpace(c))
                        sb.Append(c);
                }
                tooLong = sb.Length > _limits.MaxExtractedTextChars;
                return tooLong;
            },
            token).ConfigureAwait(false);

        if (read.LimitExceeded)
            return Fail("File exceeds security size limits.");
        if (tooLong)
            return TextLimitExceeded();

        return new DocuTrustFileCheckResult { IsClean = true, Page = sb.ToString(), Message = "Strings extracted from legacy/binary format.", IsScanned = true };
    }

    private enum OfficeContainer
    {
        Unsupported,
        Compound,
        Package,
    }
}
