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

## 2. Advanced PDF Scanning

Behind the scenes, DocuTrust uses `PdfPig` to perform behavioral analysis.

### Features
- Detects `/OpenAction` with JavaScript.
- Identifies `/Launch` commands.
- Flags suspicious embedded files and remote resource triggers.
- Integrity checks for encrypted or corrupted PDFs.

```csharp
// Internal scanners can be accessed if registered as concrete types 
// or through the internal scanners (DocuTrustPdfScanner).
```

## 3. Microsoft Office Scanning

Using `Open-XML-SDK`, DocuTrust parses `.docx`, `.xlsx`, and `.pptx` files. It also handles legacy binary formats (`.doc`, `.xls`).

### Features
- **VBA Macro Detection:** Flags any `vbaProject.bin` entries.
- **DDE Check:** Searches for Dynamic Data Exchange fields often used in phishing.
- **Embedded Payloads:** Scans for embedded executables or suspicious scripts.
- **Legacy Heuristics:** Uses string analysis to find malicious keywords in old formats.

### Design Decision
Office files are essentially ZIP packages. DocuTrust performs a two-pass check: first as a ZIP archive to find hidden parts, then as a structured document to find malicious XML elements.