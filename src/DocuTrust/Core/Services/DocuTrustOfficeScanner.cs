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
using DocuTrust.Exceptions;

namespace DocuTrust.Core.Services;

/// <summary>
/// Specialized scanner for Microsoft Office files. Handles both the modern OpenXML and the old-school legacy formats.
/// </summary>
internal class DocuTrustOfficeScanner : IDocuTrustContentFile
{
    private const long MaxFileSizeBytes = 100 * 1024 * 1024; // 100 MB
    private const long MaxPartSizeBytes = 20 * 1024 * 1024; // 20 MB per package part
    private const int MaxPackageEntries = 5000;

    public async Task<DocuTrustFileCheckResult> GetPageAsync(int pageNumber, int allPages, IFormFile file)
    {
        try
        {
            if (file.Length > MaxFileSizeBytes)
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds security size limits.", IsScanned = true };
            }

            using var stream = file.OpenReadStream();
            byte[] header = new byte[4];
            _ = await stream.ReadAsync(header, 0, 4);
            stream.Position = 0;

            // ZIP (Modern OpenXML)
            if (header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04)
            {
                return ExtractModernText(stream);
            }
            else
            {
                return await ExtractLegacyTextAsync(stream);
            }
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Failed to extract content from Office document.", ex);
        }
    }

    public async Task<DocuTrustFileCheckResult> ScanFileContentAsync(IFormFile file)
    {
        try
        {
            if (file.Length > MaxFileSizeBytes)
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds security scan size limit.", IsScanned = true };
            }

            using var stream = file.OpenReadStream();
            byte[] header = new byte[8];
            _ = await stream.ReadAsync(header, 0, 8);
            stream.Position = 0;

            // Legacy OLE Header
            if (header.SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }))
            {
                return await ScanLegacyOfficeAsync(stream);
            }

            // Modern OpenXML (ZIP)
            if (header[0] == 0x50 && header[1] == 0x4B && (header[2] == 0x03 || header[2] == 0x01))
            {
                return ScanModernOffice(stream);
            }

            return new DocuTrustFileCheckResult { IsClean = false, Message = "Unsupported or malformed Office format.", IsScanned = true };
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Deep scan of Office document failed.", ex);
        }
    }

    private DocuTrustFileCheckResult ScanModernOffice(Stream stream)
    {
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Read, true))
        {
            if (zip.Entries.Count > MaxPackageEntries)
                return new DocuTrustFileCheckResult { IsClean = false, Message = "Package contains excessive number of parts.", IsScanned = true };

            foreach (var entry in zip.Entries)
            {
                if (entry.Length > MaxPartSizeBytes)
                    return new DocuTrustFileCheckResult { IsClean = false, Message = $"Part '{entry.FullName}' exceeds safety size limit.", IsScanned = true };

                if (entry.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                    return new DocuTrustFileCheckResult { IsClean = false, Message = "VBA Macros detected in package.", IsScanned = true };

                if (entry.FullName.Contains("embeddings/"))
                {
                    string ext = Path.GetExtension(entry.FullName).ToLowerInvariant();
                    string[] maliciousExts = { ".exe", ".vbs", ".ps1", ".bat", ".com", ".scr", ".js", ".jse", ".wsf", ".wsh", ".vbe", ".jar" };
                    if (maliciousExts.Contains(ext))
                        return new DocuTrustFileCheckResult { IsClean = false, Message = $"Suspicious embedded executable found: {entry.FullName}", IsScanned = true };
                }
            }
        }

        stream.Position = 0;
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
            // Word
            try
            {
                using var doc = WordprocessingDocument.Open(stream, false, settings);
                return InspectWord(doc);
            }
            catch (InvalidDataException) { stream.Position = 0; }

            // Excel
            try
            {
                using var doc = SpreadsheetDocument.Open(stream, false, settings);
                return InspectExcel(doc);
            }
            catch (InvalidDataException) { stream.Position = 0; }

            // PowerPoint
            try
            {
                using var doc = PresentationDocument.Open(stream, false, settings);
                return InspectPowerPoint(doc);
            }
            catch (InvalidDataException) { stream.Position = 0; }

            return new DocuTrustFileCheckResult
            {
                IsClean = false,
                Message = "File format unrecognized or structurally invalid for Office documents",
                IsScanned = true
            };
        }
        catch (Exception ex)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = $"Structural deep scan failed: {ex.Message}", IsScanned = true };
        }
    }

    private DocuTrustFileCheckResult InspectWord(WordprocessingDocument doc)
    {
        var parts = new List<OpenXmlPart> { doc.MainDocumentPart! };
        parts.AddRange(doc.MainDocumentPart!.HeaderParts);
        parts.AddRange(doc.MainDocumentPart!.FooterParts);

        foreach (var part in parts)
        {
            if (PartContainsDDE(part))
                return new DocuTrustFileCheckResult { IsClean = false, Message = "DDE/DDEAUTO field code detected.", IsScanned = true };
        }

        if (HasSuspiciousRelationships(doc.MainDocumentPart))
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Suspicious external relationships or remote templates found.", IsScanned = true };

        return new DocuTrustFileCheckResult { IsClean = true, Message = "Word document is clean.", IsScanned = true };
    }

    private DocuTrustFileCheckResult InspectExcel(SpreadsheetDocument doc)
    {
        if (HasSuspiciousRelationships(doc.WorkbookPart))
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Suspicious external workbook links detected.", IsScanned = true };

        return new DocuTrustFileCheckResult { IsClean = true, Message = "Excel document is clean.", IsScanned = true };
    }

    private DocuTrustFileCheckResult InspectPowerPoint(PresentationDocument doc)
    {
        if (HasSuspiciousRelationships(doc.PresentationPart))
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Suspicious external presentation links detected.", IsScanned = true };

        return new DocuTrustFileCheckResult { IsClean = true, Message = "PowerPoint document is clean.", IsScanned = true };
    }

    private bool PartContainsDDE(OpenXmlPart part)
    {
        try
        {
            using var partStream = part.GetStream();
            using var reader = XmlReader.Create(partStream);
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "instrText")
                {
                    string content = reader.ReadElementContentAsString();
                    if (content.Contains("DDE") || content.Contains("DDEAUTO")) return true;
                }
            }
        }
        catch { }
        return false;
    }

    private bool HasSuspiciousRelationships(OpenXmlPartContainer? container)
    {
        if (container == null) return false;

        foreach (var rel in container.ExternalRelationships)
        {
            string target = rel.Uri.ToString().ToLowerInvariant();
            if (target.StartsWith("file://") || target.StartsWith("mhtml:") || target.StartsWith("its:") || target.Contains(".."))
                return true;

            if (rel.RelationshipType.Contains("attachedTemplate") || rel.RelationshipType.Contains("oleObject"))
                return true;
        }

        return container.Parts.Any(p => HasSuspiciousRelationships(p.OpenXmlPart));
    }

    private async Task<DocuTrustFileCheckResult> ScanLegacyOfficeAsync(Stream stream)
    {
        byte[] data = new byte[stream.Length];
        _ = await stream.ReadAsync(data, 0, (int)stream.Length);

        string ascii = Encoding.ASCII.GetString(data);
        string utf16 = Encoding.Unicode.GetString(data);

        string[] suspiciousKeywords = {
            "VBAProject", "_VBA_PROJECT_CUR", "PROJECTwm",
            "AutoOpen", "AutoExec", "Document_Open", "Workbook_Open",
            "Execute", "Shell", "CreateObject", "WScript.Shell", "powershell.exe"
        };

        foreach (var keyword in suspiciousKeywords)
        {
            if (ascii.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0 ||
                utf16.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = $"Legacy malicious indicator detected: '{keyword}'.", IsScanned = true };
            }
        }

        if (ascii.Contains("\x01Ole10Native"))
            return new DocuTrustFileCheckResult { IsClean = false, Message = "Legacy file contains embedded OLE objects.", IsScanned = true };

        return new DocuTrustFileCheckResult { IsClean = true, Message = "Legacy heuristics passed.", IsScanned = true };
    }

    private DocuTrustFileCheckResult ExtractModernText(Stream stream)
    {
        var sb = new StringBuilder();
        try
        {
            // Word
            try
            {
                using var doc = WordprocessingDocument.Open(stream, false);
                if (doc.MainDocumentPart?.Document?.Body != null)
                {
                    var text = doc.MainDocumentPart.Document.Body.InnerText;
                    if (!string.IsNullOrEmpty(text)) sb.Append(text);
                }
            }
            catch { stream.Position = 0; }

            // Excel
            if (sb.Length == 0)
            {
                try
                {
                    using var doc = SpreadsheetDocument.Open(stream, false);
                    var workbookPart = doc.WorkbookPart;
                    var sheets = workbookPart?.Workbook?.Sheets;
                    if (sheets != null && workbookPart != null)
                    {
                        foreach (var sheet in sheets.Cast<Sheet>())
                        {
                            if (sheet.Id != null)
                            {
                                var worksheetPart = (WorksheetPart)workbookPart.GetPartById(sheet.Id!);
                                var text = worksheetPart.Worksheet?.InnerText;
                                if (!string.IsNullOrEmpty(text)) sb.Append(text);
                            }
                        }
                    }
                }
                catch { stream.Position = 0; }
            }

            // PowerPoint
            if (sb.Length == 0)
            {
                try
                {
                    using var doc = PresentationDocument.Open(stream, false);
                    var presentationPart = doc.PresentationPart;
                    var slides = presentationPart?.Presentation?.SlideIdList;
                    if (slides != null && presentationPart != null)
                    {
                        foreach (var slideId in slides.Cast<SlideId>())
                        {
                            if (slideId.RelationshipId != null)
                            {
                                var slidePart = (SlidePart)presentationPart.GetPartById(slideId.RelationshipId!);
                                var text = slidePart.Slide?.InnerText;
                                if (!string.IsNullOrEmpty(text)) sb.Append(text);
                            }
                        }
                    }
                }
                catch { stream.Position = 0; }
            }

            return new DocuTrustFileCheckResult { IsClean = true, Page = sb.ToString(), Message = "Text extracted from OpenXML format.", IsScanned = true };
        }
        catch (Exception ex)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = $"Text extraction error: {ex.Message}", IsScanned = true };
        }
    }

    private async Task<DocuTrustFileCheckResult> ExtractLegacyTextAsync(Stream stream)
    {
        byte[] data = new byte[stream.Length];
        _ = await stream.ReadAsync(data, 0, (int)stream.Length);
        string raw = Encoding.ASCII.GetString(data);

        var sb = new StringBuilder();
        foreach (char c in raw)
        {
            if (char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsWhiteSpace(c))
                sb.Append(c);
        }

        return new DocuTrustFileCheckResult { IsClean = true, Page = sb.ToString(), Message = "Strings extracted from legacy/binary format.", IsScanned = true };
    }
}
