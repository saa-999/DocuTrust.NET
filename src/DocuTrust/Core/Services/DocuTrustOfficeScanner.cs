using System.Buffers;
using System.IO.Compression;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Http;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml.Presentation;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Models;
using DocuTrust.Core.Constants;
using DocuTrust.Core.Scanning;
using DocuTrust.Exceptions;


namespace DocuTrust.Core.Services;

internal class DocuTrustOfficeScanner : IDocuTrustContentFile
{

    private const string OleNativeStreamName = "\u0001Ole10Native";

    private static readonly KeywordSet LegacyIndicators = new(
    [
        "VBAProject", "_VBA_PROJECT_CUR", "PROJECTwm",
        "AutoOpen", "AutoExec", "Document_Open", "Workbook_Open",
        "Execute", "Shell", "CreateObject", "WScript.Shell", "powershell.exe",
        OleNativeStreamName,
        EncryptedPackageStreamName, EncryptionInfoStreamName
    ]);

    // Password-protected OOXML is a CFB holding these two streams; the content itself is ciphertext.
    private const string EncryptedPackageStreamName = "EncryptedPackage";
    private const string EncryptionInfoStreamName = "EncryptionInfo";

    private static DocuTrustFileCheckResult EncryptedResult() => new()
    {
        IsClean = false,
        IsEncrypted = true,
        IsScanned = false,
        Message = "Encrypted (password-protected) Office document: content cannot be scanned.",
    };

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


    public async Task<DocuTrustFileCheckResult> GetPageAsync(int pageNumber, int allPages, IFormFile file, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            if (file.Length > FileSize.MaxFileSizeBytes)
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds security size limits.", IsScanned = true };
            }

            // Every pass opens a fresh stream from the IFormFile: no Position resets, works for non-seekable streams.
            byte[] header = await ReadHeaderAsync(file, 4, token);

            if (header.Length == 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04)
            {
                // Enforce real decompressed sizes before the SDK loads any part into a DOM.
                var (failure, kind) = await InspectPackageAsync(file, token);
                if (failure != null)
                    return failure;

                return ExtractModernText(file, kind, token);
            }

            using var stream = file.OpenReadStream();
            return await ExtractLegacyTextAsync(stream, token);
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
            if (file.Length > FileSize.MaxFileSizeBytes)
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds security scan size limit.", IsScanned = true };
            }

            byte[] header = await ReadHeaderAsync(file, 8, token);

            if (header.AsSpan().SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }))
            {
                // Encryption flags of .doc/.xls/.ppt and encrypted OOXML need random access to the CFB structure.
                using (var cfb = file.OpenReadStream())
                {
                    if (CompoundFileInspector.Inspect(cfb) == CompoundFileVerdict.Encrypted)
                        return EncryptedResult();
                }

                using var stream = file.OpenReadStream();
                return await ScanLegacyOfficeAsync(stream, token);
            }

            if (header.Length >= 4 && header[0] == 0x50 && header[1] == 0x4B && (header[2] == 0x03 || header[2] == 0x01))
            {
                return await ScanModernOfficeAsync(file, token);
            }

            return new DocuTrustFileCheckResult { IsClean = false, Message = "Unsupported or malformed Office format.", IsScanned = true };
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

    private static async Task<byte[]> ReadHeaderAsync(IFormFile file, int count, CancellationToken token)
    {
        using var stream = file.OpenReadStream();
        var header = new byte[count];
        int read = await stream.ReadAtLeastAsync(header, count, throwOnEndOfStream: false, token);
        return read == count ? header : header[..read];
    }

    private async Task<(DocuTrustFileCheckResult? Failure, OfficeDocumentKind Kind)> InspectPackageAsync(IFormFile file, CancellationToken token)
    {
        using var stream = file.OpenReadStream();

        // ZipArchive needs random access to the central directory; fail closed instead of throwing.
        if (!stream.CanSeek)
            return (new DocuTrustFileCheckResult { IsClean = false, Message = "Office package scanning requires a seekable stream.", IsScanned = false }, OfficeDocumentKind.Unknown);

        var verdict = await new OfficePackageInspector(_bufferPool, _limits).InspectAsync(stream, token);
        return verdict.Threat == null
            ? (null, verdict.Kind)
            : (new DocuTrustFileCheckResult { IsClean = false, Message = verdict.Threat, IsScanned = true }, verdict.Kind);
    }

    private async Task<DocuTrustFileCheckResult> ScanModernOfficeAsync(IFormFile file, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var (failure, kind) = await InspectPackageAsync(file, token);
        if (failure != null)
            return failure;

        var settings = new OpenSettings
        {
            AutoSave = false,
            MarkupCompatibilityProcessSettings = new MarkupCompatibilityProcessSettings(
                MarkupCompatibilityProcessMode.NoProcess,
                FileFormatVersions.Microsoft365
            )
        };

        try
        {
            // Open exactly the document type the package declares; any failure is fail-closed below.
            using var stream = file.OpenReadStream();
            switch (kind)
            {
                case OfficeDocumentKind.Word:
                    using (var doc = WordprocessingDocument.Open(stream, false, settings))
                        return InspectWord(doc, token);
                case OfficeDocumentKind.Excel:
                    using (var doc = SpreadsheetDocument.Open(stream, false, settings))
                        return InspectExcel(doc, token);
                case OfficeDocumentKind.PowerPoint:
                    using (var doc = PresentationDocument.Open(stream, false, settings))
                        return InspectPowerPoint(doc, token);
                default:
                    return new DocuTrustFileCheckResult
                    {
                        IsClean = false,
                        Message = "File format unrecognized or structurally invalid for Office documents",
                        IsScanned = true
                    };
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // Exception text (part URIs, parser internals) is never copied into the result.
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Structural deep scan failed: the package is not a valid document of its declared type.", IsScanned = true };
        }
    }

    // The first pass (OfficePackageInspector) already checked every part's content types, relationships, field
    // codes and embedded payloads. Opening the matching SDK type here confirms the package parses as that type;
    // any failure is treated as not-clean by the caller.
    private static DocuTrustFileCheckResult InspectWord(WordprocessingDocument doc, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        _ = doc.MainDocumentPart;
        return new DocuTrustFileCheckResult { IsClean = true, Message = "Word document is clean.", IsScanned = true };
    }

    private static DocuTrustFileCheckResult InspectExcel(SpreadsheetDocument doc, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        _ = doc.WorkbookPart;
        return new DocuTrustFileCheckResult { IsClean = true, Message = "Excel document is clean.", IsScanned = true };
    }

    private static DocuTrustFileCheckResult InspectPowerPoint(PresentationDocument doc, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        _ = doc.PresentationPart;
        return new DocuTrustFileCheckResult { IsClean = true, Message = "PowerPoint document is clean.", IsScanned = true };
    }

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
            return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds security scan size limit.", IsScanned = true };

        if (indicator is EncryptedPackageStreamName or EncryptionInfoStreamName)
            return EncryptedResult();

        if (indicator == OleNativeStreamName)
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Legacy file contains embedded OLE objects.", IsScanned = true };

        if (indicator != null)
            return new DocuTrustFileCheckResult { IsClean = false, Message = $"Legacy malicious indicator detected: '{indicator}'.", IsScanned = true };

        return new DocuTrustFileCheckResult { IsClean = true, Message = "Legacy heuristics passed.", IsScanned = true };
    }

    private DocuTrustFileCheckResult ExtractModernText(IFormFile file, OfficeDocumentKind kind, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var sb = new StringBuilder();
        try
        {
            if (kind == OfficeDocumentKind.Word)
            {
                try
                {
                using var stream = file.OpenReadStream();
                using var doc = WordprocessingDocument.Open(stream, false);
                if (doc.MainDocumentPart?.Document?.Body != null)
                {
                    token.ThrowIfCancellationRequested();
                    var text = doc.MainDocumentPart.Document.Body.InnerText;
                    if (!string.IsNullOrEmpty(text)) sb.Append(text);
                }
            }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            if (kind == OfficeDocumentKind.Excel)
            {
                try
                {
                    using var stream = file.OpenReadStream();
                using var doc = SpreadsheetDocument.Open(stream, false);
                    var workbookPart = doc.WorkbookPart;
                    var sheets = workbookPart?.Workbook?.Sheets;
                    if (sheets != null && workbookPart != null)
                    {
                        foreach (var sheet in sheets.Cast<Sheet>())
                        {
                            token.ThrowIfCancellationRequested();
                            if (sheet.Id != null)
                            {
                                var worksheetPart = (WorksheetPart)workbookPart.GetPartById(sheet.Id!);
                                var text = worksheetPart.Worksheet?.InnerText;
                                if (!string.IsNullOrEmpty(text)) sb.Append(text);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            if (kind == OfficeDocumentKind.PowerPoint)
            {
                try
                {
                    using var stream = file.OpenReadStream();
                using var doc = PresentationDocument.Open(stream, false);
                    var presentationPart = doc.PresentationPart;
                    var slides = presentationPart?.Presentation?.SlideIdList;
                    if (slides != null && presentationPart != null)
                    {
                        foreach (var slideId in slides.Cast<SlideId>())
                        {
                            token.ThrowIfCancellationRequested();
                            if (slideId.RelationshipId != null)
                            {
                                var slidePart = (SlidePart)presentationPart.GetPartById(slideId.RelationshipId!);
                                var text = slidePart.Slide?.InnerText;
                                if (!string.IsNullOrEmpty(text)) sb.Append(text);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            return new DocuTrustFileCheckResult { IsClean = true, Page = sb.ToString(), Message = "Text extracted from OpenXML format.", IsScanned = true };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Text extraction failed: the document could not be parsed.", IsScanned = true };
        }
    
    }

    private async Task<DocuTrustFileCheckResult> ExtractLegacyTextAsync(Stream stream, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var sb = new StringBuilder();
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
                return false;
            },
            token).ConfigureAwait(false);

        if (read.LimitExceeded)
            return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds security size limits.", IsScanned = true };

        return new DocuTrustFileCheckResult { IsClean = true, Page = sb.ToString(), Message = "Strings extracted from legacy/binary format.", IsScanned = true };
    }
    

}
