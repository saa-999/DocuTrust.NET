# API Reference

## IDocuTrustFileValidator

Main entry point for file validation.

| Method | Parameters | Return | Description |
| :--- | :--- | :--- | :--- |
| `ValidateFileAsync` | `IFormFile file, string expectedExt` | `DocuTrustValidationResult` | Validates an uploaded file's signature against the expected extension. |
| `ValidateFilePathAsync` | `string filePath, string expectedExt` | `DocuTrustValidationResult` | Validates a file on disk. |
| `ValidateFileStreamAsync` | `Stream stream, string expectedExt` | `DocuTrustValidationResult` | Validates a raw stream. |
| `GetFileTypeAsync` | `string filePath` | `DocuTrustValidationResult` | Detects the MIME type and extension of a file. |

## DocuTrustValidationResult

| Property | Type | Description |
| :--- | :--- | :--- |
| `IsValid` | `bool` | True if the file signature matches the expectation. |
| `ActualMimeType` | `string?` | The detected MIME type (e.g., "application/pdf"). |
| `ActualExtension` | `string?` | The detected extension (e.g., "pdf"). |
| `Message` | `string?` | Descriptive result message. |

## Specialized Content Scanning (Internal)

These scanners are used by the library internally but represent the core logic.

### DocuTrustPdfScanner
- `ScanFileContentAsync`: Deep behavioral scan.
- `GetPageAsync`: Content extraction per page.

### DocuTrustOfficeScanner
- `ScanFileContentAsync`: Macro and DDE detection.
- `GetPageAsync`: Content extraction.