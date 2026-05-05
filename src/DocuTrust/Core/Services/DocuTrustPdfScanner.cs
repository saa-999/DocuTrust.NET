using System.Text;
using Microsoft.AspNetCore.Http;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.DocumentLayoutAnalysis.WordExtractor;
using UglyToad.PdfPig.Exceptions;
using UglyToad.PdfPig.Tokens;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Models;
using DocuTrust.Exceptions;

namespace DocuTrust.Core.Services;

internal class DocuTrustPdfScanner : IDocuTrustContentFile
{
    private const long MaxPdfSizeBytes = 150 * 1024 * 1024;
    private const long MaxEmbeddedStreamSize = 25 * 1024 * 1024;
    private const int MaxNestingDepth = 15;

    public async Task<DocuTrustFileCheckResult> GetPageAsync(int pageNumber, int allPages, IFormFile file, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            var encryptionResult = await CheckEncryptionAsync(file, token);
            if (encryptionResult.IsEncrypted || !encryptionResult.IsScanned || (encryptionResult.Message?.Contains("Integrity") ?? false))
                return encryptionResult;

            using var stream = file.OpenReadStream();
            using var pdf = PdfDocument.Open(stream);

            if (allPages != 0 || pageNumber == 0)
            {
                var allText = new StringBuilder();
                foreach (var page in pdf.GetPages())
                {
                    token.ThrowIfCancellationRequested();
                    var words = page.GetWords(NearestNeighbourWordExtractor.Instance);
                    allText.AppendLine(string.Join(" ", words.Select(w => w.Text)));
                }
                return new DocuTrustFileCheckResult
                {
                    IsClean = true,
                    Page = allText.ToString(),
                    Message = "Extracted all pages.",
                    IsScanned = true
                };
            }
            else
            {
                token.ThrowIfCancellationRequested();
                if (pageNumber > pdf.NumberOfPages || pageNumber < 1)
                    return new DocuTrustFileCheckResult { IsClean = false, Message = "Requested page index out of range.", IsScanned = true };

                var page = pdf.GetPage(pageNumber);
                var words = page.GetWords(NearestNeighbourWordExtractor.Instance);
                return new DocuTrustFileCheckResult
                {
                    IsClean = true,
                    Page = string.Join(" ", words.Select(w => w.Text)),
                    Message = $"Extracted page {pageNumber}.",
                    IsScanned = true
                };
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Failed to extract text from PDF.", ex);
        }
    }

    public async Task<DocuTrustFileCheckResult> ScanFileContentAsync(IFormFile file, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            var integrityCheck = await CheckEncryptionAsync(file, token);
            if (!integrityCheck.IsScanned || !integrityCheck.IsClean || integrityCheck.IsEncrypted)
                return integrityCheck;

            using var stream = file.OpenReadStream();
            using var pdf = PdfDocument.Open(stream);
            var catalog = pdf.Structure.Catalog.CatalogDictionary;

            if (ScanCatalogActions(catalog, pdf, out string actionMessage, token))
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = actionMessage, IsScanned = true };
            }

            if (catalog.TryGet(NameToken.Names, out IToken? namesToken))
            {
                if (IsNamesDictionaryMalicious(namesToken, pdf, out string namesMessage, token))
                {
                    return new DocuTrustFileCheckResult { IsClean = false, Message = namesMessage, IsScanned = true };
                }
            }

            if (catalog.TryGet(NameToken.Create("AA"), out IToken? _))
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = "Suspicious Additional Actions (/AA) detected in catalog.", IsScanned = true };
            }

            if (catalog.TryGet(NameToken.Create("AcroForm"), out IToken? acroFormToken))
            {
                if (IsAcroFormSuspicious(acroFormToken, pdf, token))
                {
                    return new DocuTrustFileCheckResult { IsClean = false, Message = "Suspicious scripts or embedded data found in AcroForm.", IsScanned = true };
                }
            }

            foreach (var page in pdf.GetPages())
            {
                token.ThrowIfCancellationRequested();
                if (ScanPageForAnomalies(page, pdf, out string pageMessage, token))
                {
                    return new DocuTrustFileCheckResult { IsClean = false, Message = pageMessage, IsScanned = true };
                }
            }

            return new DocuTrustFileCheckResult { IsClean = true, Message = "The PDF file passed behavioral analysis.", IsScanned = true };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Deep scan of PDF failed.", ex);
        }
    }

    private async Task<DocuTrustFileCheckResult> CheckEncryptionAsync(IFormFile file, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (file.Length > MaxPdfSizeBytes)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds maximum safety size limit.", IsScanned = true };
        }

        try
        {
            using var stream = file.OpenReadStream();
            byte[] header = new byte[5];
            token.ThrowIfCancellationRequested();
            if (await stream.ReadAsync(header, 0, 5, token) < 5 || Encoding.ASCII.GetString(header) != "%PDF-")
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = "Invalid PDF header signature.", IsScanned = true };
            }
            stream.Position = 0;

            using (PdfDocument.Open(stream, new ParsingOptions()))
            {
                return new DocuTrustFileCheckResult { IsEncrypted = false, Message = "The PDF file is not encrypted.", IsScanned = true, IsClean = true };
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (PdfDocumentEncryptedException)
        {
            return new DocuTrustFileCheckResult { IsEncrypted = true, Message = "The PDF file is encrypted.", IsScanned = true, IsClean = true };
        }
        catch (Exception ex)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = $"Integrity check failed: {ex.Message}", IsScanned = true };
        }
    }

    private bool ScanCatalogActions(DictionaryToken catalog, PdfDocument pdf, out string message, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        message = string.Empty;
        if (catalog.TryGet(NameToken.OpenAction, out IToken? openAction))
        {
            if (IsActionMalicious(openAction, pdf, out message, 0, token))
            {
                message = $"Malicious OpenAction: {message}";
                return true;
            }
        }
        return false;
    }

    private bool ScanPageForAnomalies(Page page, PdfDocument pdf, out string message, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        message = string.Empty;
        if (page.Dictionary != null && page.Dictionary.TryGet(NameToken.Create("AA"), out _))
        {
            message = $"Suspicious page-level triggers (/AA) on page {page.Number}.";
            return true;
        }

        if (page.Dictionary != null && page.Dictionary.TryGet(NameToken.Annots, out IToken? annotsToken))
        {
            if (IsAnnotationListMalicious(annotsToken, pdf, out message, token))
            {
                message = $"Malicious annotation on page {page.Number}: {message}";
                return true;
            }
        }

        return false;
    }

    private bool IsActionMalicious(IToken token, PdfDocument pdf, out string message, int depth, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        message = string.Empty;
        if (depth > MaxNestingDepth) return false;

        var actionDict = ResolveToDictionary(token, pdf, cancellationToken);
        if (actionDict == null) return false;

        if (actionDict.TryGet(NameToken.S, out NameToken? s) && s != null)
        {
            string actionType = s.Data;
            if (actionType == "JavaScript" || actionType == "JS")
            {
                message = "Embedded JavaScript detected.";
                return true;
            }
            if (actionType == "Launch")
            {
                message = "External process launch command (/Launch) detected.";
                return true;
            }
            if (actionType == "GoToR" || actionType == "ImportData")
            {
                message = $"Remote resource action (/{actionType}) detected.";
                return true;
            }
        }

        if (actionDict.TryGet(NameToken.Create("Next"), out IToken? next))
        {
            return IsActionMalicious(next, pdf, out message, depth + 1, cancellationToken);
        }

        return false;
    }

    private bool IsNamesDictionaryMalicious(IToken token, PdfDocument pdf, out string message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        message = string.Empty;
        var namesDict = ResolveToDictionary(token, pdf, cancellationToken);
        if (namesDict == null) return false;

        if (namesDict.TryGet(NameToken.EmbeddedFiles, out _))
        {
            message = "Embedded files (payload carrier) detected in Names dictionary.";
            return true;
        }

        if (namesDict.TryGet(NameToken.JavaScript, out _) || namesDict.TryGet(NameToken.Create("JS"), out _))
        {
            message = "JavaScript tree detected in Names dictionary.";
            return true;
        }

        return false;
    }

    private bool IsAnnotationListMalicious(IToken annotsToken, PdfDocument pdf, out string message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        message = string.Empty;
        if (annotsToken is ArrayToken array)
        {
            foreach (var item in array.Data)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var annot = ResolveToDictionary(item, pdf, cancellationToken);
                if (annot == null) continue;

                if (annot.TryGet(NameToken.A, out IToken? action) && IsActionMalicious(action, pdf, out message, 0, cancellationToken)) return true;
                if (annot.TryGet(NameToken.Create("AA"), out _))
                {
                    message = "Annotation with automatic trigger (/AA) detected.";
                    return true;
                }
                
                if (annot.TryGet(NameToken.Subtype, out NameToken? subtype) && subtype != null && subtype.Data == "FileAttachment")
                {
                    message = "File attachment annotation detected.";
                    return true;
                }
            }
        }
        return false;
    }

    private bool IsAcroFormSuspicious(IToken token, PdfDocument pdf, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acroForm = ResolveToDictionary(token, pdf, cancellationToken);
        if (acroForm == null) return false;

        if (acroForm.TryGet(NameToken.Create("XFA"), out _)) return true;

        return acroForm.TryGet(NameToken.Create("JS"), out _) || acroForm.TryGet(NameToken.Create("JavaScript"), out _);
    }

    private DictionaryToken? ResolveToDictionary(IToken token, PdfDocument pdf, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (token is DictionaryToken d) return d;
            if (token is IndirectReferenceToken r)
            {
                var obj = pdf.Structure.GetObject(r.Data);
                if (obj.Data is DictionaryToken dict) return dict;
                if (obj.Data is StreamToken stream)
                {
                    if (stream.StreamDictionary.TryGet(NameToken.Length, out NumericToken? len) && len != null && len.Long > MaxEmbeddedStreamSize)
                    {
                        return null;
                    }
                    return stream.StreamDictionary;
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch { }
        return null;
    }
}
