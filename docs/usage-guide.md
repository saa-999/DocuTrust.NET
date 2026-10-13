# Usage Guide

DocuTrust.NET provides several layers of protection. This guide walkthrough the main components.

## 1. General File Validation

The `IDocuTrustFileValidator` is your primary interface. It uses the `FileSignatures` library to verify that a file's content matches its extension.

### Why this way?
Extensions are easily spoofed. By checking the "magic bytes" at the start of the file, we ensure that a `.pdf` is actually a PDF and not a renamed executable.

```csharp
// Check a file on disk
var result = await _validator.ValidateFilePathAsync("path/to/file.pdf", ".pdf");
```

### Security behaviour
- `expectedExtension` is required. An empty value returns `IsValid = false` (the detected type is still reported).
- For uploads, the client file name must carry the expected extension when it has one (`invoice.pdf.exe` or
  `invoice.html` with PDF bytes are rejected; names without an extension such as `blob` are accepted).
- ZIP (OOXML) and OLE containers larger than 100 MB are rejected before format inspection.
- `ValidateFileStreamAsync` restores your stream's position.
- Paths are trusted input: canonicalise and confine them yourself (no traversal protection). FIFOs and other
  non-regular files are rejected without being opened.
- Validation identifies the file type only. It does not scan content for macros or scripts.

## 2. Advanced PDF Scanning

Behind the scenes, DocuTrust uses `PdfPig` to perform behavioral analysis.

### Features
- A raw-byte pre-scan (before parsing) finds dangerous names anywhere outside stream bodies, including `#xx`-escaped
  names, unreferenced objects, older incremental-update revisions and appended ZIP archives (polyglots).
- A structural walk inspects every object reachable from the catalog (pages, annotations, outlines, name trees,
  form fields, compressed object streams) for JavaScript, `/Launch`, remote/embedded-document actions, form
  submission, multimedia actions, `/AA` triggers, XFA, embedded files and dangerous URI targets.
- Encrypted PDFs that cannot be decrypted are reported `IsClean = false`, `IsEncrypted = true`.
- Text extraction runs the full scan first and is limited in pages, glyphs per page and characters.
- Every limit, parse error or timeout fails closed (`IsClean = false`).

```csharp
// Internal scanners can be accessed if registered as concrete types 
// or through the internal scanners (DocuTrustPdfScanner).
```

## 3. Microsoft Office Scanning

Using `Open-XML-SDK`, DocuTrust parses `.docx`, `.xlsx`, and `.pptx` files. It also handles legacy binary formats (`.doc`, `.xls`).

### Features
- **VBA/XLM Macro Detection:** macro content types, `vbaProject`/`wordVbaData`/`xlMacrosheet` relationships,
  `vbaProject.bin`, `vbaData.xml` and Excel 4.0 macro sheets, however the parts are named.
- **DDE Check:** field codes in every XML part (split runs, `fldSimple`, nested-field obfuscation), Excel DDE links
  and DDE formulas.
- **External content:** remote templates/frames/sub-documents, external OLE objects, UNC targets, protocol
  handlers (`ms-msdt:`, `search-ms:`, …) and PowerPoint `ppaction://program`.
- **Embedded Payloads:** executables by extension and by content (PE/ELF/Mach-O/LNK headers), OLE Package and
  Equation Editor objects, and embedded packages inspected recursively.
- **Encrypted documents:** password-protected `.docx/.xlsx/.pptx` and encrypted `.doc/.xls/.ppt` are reported
  `IsClean = false`, `IsEncrypted = true`.
- **Legacy Heuristics:** streamed keyword search (ASCII and UTF-16LE) in old binary formats.

### Design Decision
Office files are essentially ZIP packages. DocuTrust performs a two-pass check: first a bounded pass over every
part of the ZIP (real decompressed sizes, a total budget and a compression-ratio limit against zip bombs, content
types, relationships, XML content and payload sniffing), then the OpenXML SDK confirms the package is a valid
document of its declared type. Any limit, parse error or timeout fails closed.