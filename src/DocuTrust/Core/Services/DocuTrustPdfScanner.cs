using System.Buffers;
using System.Text;
using Microsoft.AspNetCore.Http;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.DocumentLayoutAnalysis.WordExtractor;
using UglyToad.PdfPig.Exceptions;
using UglyToad.PdfPig.Tokens;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Models;
using DocuTrust.Core.Constants;
using DocuTrust.Core.Scanning;
using DocuTrust.Exceptions;

namespace DocuTrust.Core.Services;

internal class DocuTrustPdfScanner : IDocuTrustContentFile
{
    private readonly ArrayPool<byte> _bufferPool;

    public DocuTrustPdfScanner() : this(ArrayPool<byte>.Shared)
    {
    }

    internal DocuTrustPdfScanner(ArrayPool<byte> bufferPool)
    {
        _bufferPool = bufferPool;
    }

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
            // Raw bytes first: obviously hostile files never reach the parser, and objects the parser never
            // surfaces (unreferenced, older incremental revisions) are still seen.
            var rawThreat = await RawScanAsync(file, token);
            if (rawThreat != null)
                return rawThreat;

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
                if (IsAcroFormSuspicious(acroFormToken, pdf, out string formMessage, token))
                {
                    return new DocuTrustFileCheckResult { IsClean = false, Message = $"Suspicious content in AcroForm: {formMessage}", IsScanned = true };
                }
            }

            // Every object reachable from the catalog (pages, annotations, outlines, name trees, fields, objects in
            // compressed object streams) — without parsing page content streams.
            if (PdfStructureWalker.FindThreat(pdf, token) is { } structuralThreat)
            {
                return new DocuTrustFileCheckResult { IsClean = false, Message = structuralThreat, IsScanned = true };
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

    private async Task<DocuTrustFileCheckResult?> RawScanAsync(IFormFile file, CancellationToken token)
    {
        if (file.Length > FileSize.MaxPdfSizeBytes)
            return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds maximum safety size limit.", IsScanned = true };

        var scanner = new PdfRawScanner();
        ChunkReadResult read;
        using (var stream = file.OpenReadStream())
        {
            read = await PooledChunkReader.ReadAsync(
                stream, _bufferPool, overlap: 0, FileSize.MaxPdfSizeBytes,
                (window, _) => { scanner.Feed(window); return false; },
                token).ConfigureAwait(false);
        }
        scanner.Complete();

        if (read.LimitExceeded)
            return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds maximum safety size limit.", IsScanned = true };

        return scanner.Threat == null
            ? null
            : new DocuTrustFileCheckResult { IsClean = false, IsEncrypted = scanner.SawEncrypt, Message = scanner.Threat, IsScanned = true };
    }

    private async Task<DocuTrustFileCheckResult> CheckEncryptionAsync(IFormFile file, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (file.Length > FileSize.MaxPdfSizeBytes)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = "File exceeds maximum safety size limit.", IsScanned = true };
        }

        try
        {
            byte[] header = new byte[5];
            using (var headerStream = file.OpenReadStream())
            {
                token.ThrowIfCancellationRequested();
                if (await headerStream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, token) < header.Length || Encoding.ASCII.GetString(header) != "%PDF-")
                {
                    return new DocuTrustFileCheckResult { IsClean = false, Message = "Invalid PDF header signature.", IsScanned = true };
                }
            }

            // Fresh stream instead of rewinding: no Position reset on streams that cannot seek.
            using var stream = file.OpenReadStream();
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
            // The content could not be decrypted, so nothing was scanned: never report it clean.
            return new DocuTrustFileCheckResult { IsEncrypted = true, Message = "The PDF file is encrypted and cannot be scanned.", IsScanned = false, IsClean = false };
        }
        catch (Exception)
        {
            return new DocuTrustFileCheckResult { IsClean = false, Message = "A secure processing error occurred.", IsScanned = true };
        }
    }

    private bool ScanCatalogActions(DictionaryToken catalog, PdfDocument pdf, out string message, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        message = string.Empty;
        if (catalog.TryGet(NameToken.OpenAction, out IToken? openAction))
        {
            if (IsActionMalicious(openAction, pdf, out message, token))
            {
                message = $"Malicious OpenAction: {message}";
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Walks an action and its <c>/Next</c> chain (a single action or an array of actions, ISO 32000-1 §12.6.2)
    /// iteratively. Exceeding the depth limit or revisiting an object (a cycle) is treated as malicious.
    /// </summary>
    private bool IsActionMalicious(IToken root, PdfDocument pdf, out string message, CancellationToken cancellationToken)
    {
        message = string.Empty;
        var pending = new Stack<(IToken Token, int Depth)>();
        var visited = new HashSet<UglyToad.PdfPig.Core.IndirectReference>();
        pending.Push((root, 0));

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (current, depth) = pending.Pop();

            if (depth > FileSize.MaxNestingDepth)
            {
                message = "Action chain exceeds the maximum nesting depth.";
                return true;
            }

            if (current is IndirectReferenceToken reference && !visited.Add(reference.Data))
            {
                message = "Cyclic action chain detected.";
                return true;
            }

            var actionDict = ResolveToDictionary(current, pdf, cancellationToken);
            if (actionDict == null)
                continue;

            // Covers every dangerous /S type, /URI schemes and a /JS key without /S.
            if (PdfThreatRules.Inspect(actionDict) is { } threat)
            {
                message = threat;
                return true;
            }

            if (actionDict.TryGet(NameToken.Create("Next"), out IToken? next))
            {
                if (next is ArrayToken nextActions)
                {
                    foreach (var item in nextActions.Data)
                        pending.Push((item, depth + 1));
                }
                else
                {
                    pending.Push((next, depth + 1));
                }
            }
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

    private bool IsAcroFormSuspicious(IToken token, PdfDocument pdf, out string message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        message = string.Empty;
        var acroForm = ResolveToDictionary(token, pdf, cancellationToken);
        if (acroForm == null)
            return false;

        if (PdfThreatRules.Inspect(acroForm) is { } formThreat)
        {
            message = formThreat;
            return true;
        }

        if (!acroForm.TryGet(NameToken.Create("Fields"), out IToken? fieldsToken))
            return false;

        // Fields (and their /Kids) carry keystroke/format/validate/calculate scripts in /AA even without a widget.
        var pending = new Stack<(IToken Token, int Depth)>();
        var visited = new HashSet<UglyToad.PdfPig.Core.IndirectReference>();
        if (Resolve(fieldsToken, pdf) is ArrayToken roots)
            foreach (var field in roots.Data)
                pending.Push((field, 0));

        int inspected = 0;
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (current, depth) = pending.Pop();
            if (depth > FileSize.MaxNestingDepth || ++inspected > MaxFormFields)
            {
                message = "Form field tree exceeds the inspection limits.";
                return true;
            }
            if (current is IndirectReferenceToken reference && !visited.Add(reference.Data))
                continue;

            var field = ResolveToDictionary(current, pdf, cancellationToken);
            if (field == null)
                continue;

            if (PdfThreatRules.Inspect(field) is { } fieldThreat)
            {
                message = fieldThreat;
                return true;
            }
            if (field.TryGet(NameToken.A, out IToken? action) && IsActionMalicious(action, pdf, out message, cancellationToken))
                return true;

            if (field.TryGet(NameToken.Kids, out IToken? kidsToken) && Resolve(kidsToken, pdf) is ArrayToken kids)
                foreach (var kid in kids.Data)
                    pending.Push((kid, depth + 1));
        }
        return false;
    }

    private const int MaxFormFields = 100_000;

    private static IToken? Resolve(IToken token, PdfDocument pdf)
        => token is IndirectReferenceToken reference ? pdf.Structure.GetObject(reference.Data).Data : token;

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
                // The stream bytes are already in memory once GetObject returns, and the declared /Length is
                // attacker-controlled: always inspect the dictionary instead of skipping "large" objects.
                if (obj.Data is StreamToken stream)
                    return stream.StreamDictionary;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DocuTrustValidationException("Error resolving PDF token to dictionary.", ex);
        }
        return null;
    }
}
