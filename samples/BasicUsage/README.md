# BasicUsage sample

A console app that runs the public DocuTrust.NET API against a few in-memory files and prints each result.

## Run it

You need the .NET 8 SDK. From the repository root:

```bash
dotnet run --project samples/BasicUsage
```

The sample references `src/DocuTrust` directly, so it always builds against the code in this repository.

## What each step shows

1. Registers DocuTrust with `AddDocuTrust()` and resolves `IDocuTrustFileValidator` from the container.
2. Validates an `IFormFile` whose bytes and file name are both PDF. It passes.
3. Sends PNG bytes named `report.pdf`. The magic bytes win and validation fails.
4. Sends PDF bytes named `invoice.exe`. The bytes match, but the client file name does not, so validation fails.
5. Calls `ValidateFileAsync` with an empty expected extension. It fails and still reports the detected type.
6. Validates a `MemoryStream` with `ValidateFileStreamAsync` and shows that the stream position is restored.
7. Writes a temp file, validates it with `ValidateFilePathAsync`, then detects its type with `GetFileTypeAsync`.
8. Catches the `DocuTrustValidationException` thrown for a missing file.

A file of the wrong type returns `IsValid = false`. Bad input such as a null argument or a missing file throws `DocuTrustValidationException`.

## Expected output

```text
2. Real PDF upload -> IsValid=True, Type=application/pdf (pdf)
   [DocuTrust] Validation successful: application/pdf (pdf).
3. PNG renamed to .pdf -> IsValid=False, Type=image/png (png)
   [DocuTrust] Validation failed: Incorrect file format.
4. PDF bytes named .exe -> IsValid=False, Type=application/pdf (pdf)
   [DocuTrust] Validation failed: the file name extension does not match the expected type.
5. Empty expected extension -> IsValid=False, Type=application/pdf (pdf)
   [DocuTrust] Validation failed: an expected extension is required.
6. Stream -> IsValid=True, Type=application/pdf (pdf)
   [DocuTrust] Validation successful: application/pdf (pdf).
   Stream position after validation: 4
7a. File path -> IsValid=True, Type=application/pdf (pdf)
   [DocuTrust] Validation successful: application/pdf (pdf).
7b. Detected type -> IsValid=True, Type=application/pdf (pdf)
   [DocuTrust] Validation successful: application/pdf (pdf).
8. Missing file -> DocuTrustValidationException: Validation failed for the provided path.
```
