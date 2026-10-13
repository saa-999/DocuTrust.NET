<p align="center">
  <img src="assets/logo.png" alt="DocuTrust.NET logo" width="260">
</p>

<h1 align="center">DocuTrust.NET</h1>

<p align="center">Check what an uploaded file really is before your ASP.NET Core app trusts it.</p>

<p align="center">
  <a href="https://www.nuget.org/packages/DocuTrust.NET/"><img src="https://img.shields.io/nuget/v/DocuTrust.NET.svg" alt="NuGet"></a>
  <img src="https://img.shields.io/badge/.NET-8.0-512BD4.svg" alt=".NET 8.0">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/saa-999/DocuTrust.NET/actions/workflows/build.yml"><img src="https://github.com/saa-999/DocuTrust.NET/actions/workflows/build.yml/badge.svg" alt="Build"></a>
</p>

<p align="center">
  <a href="assets/docutrust-promo.mp4">
    <img src="assets/docutrust-preview.gif" alt="DocuTrust.NET promo — click to watch with sound" width="720">
  </a>
</p>

<p align="center">▶ Click to watch with sound</p>

## What is DocuTrust.NET?

DocuTrust.NET is a .NET 8 library that identifies a file by its magic bytes and tells you whether it matches the type you expect. A PNG renamed to `report.pdf` fails, and so does a real PDF uploaded as `invoice.exe`. It plugs into ASP.NET Core dependency injection and works with `IFormFile`, streams and file paths.

## Features

- Detects the real file type from its signature with [FileSignatures](https://github.com/neilharvey/FileSignatures) and returns the MIME type and extension.
- Validates ASP.NET Core uploads (`IFormFile`), any `Stream`, or a file on disk.
- For uploads, also checks the client file name. A name whose extension differs from the expected type is rejected (aliases such as `jpg`/`jpeg` and `tif`/`tiff` are accepted), as are names with control characters or `:`.
- Fails closed: an empty file or a missing expected extension never passes.
- Rejects ZIP and OLE containers over 100 MB before parsing them.
- For path-based checks, refuses empty files and anything that is not a regular file (FIFOs, devices) without opening it.
- Restores the position of a seekable stream after validation.
- Returns plain result objects. Only bad input (null arguments, missing files, read errors) throws, as `DocuTrustValidationException`.
- One-line registration with `AddDocuTrust()`.

The package also contains PDF and Office content scanners, but they are internal in this version and not part of the public API.

## Installation

```bash
dotnet add package DocuTrust.NET
```

DocuTrust.NET targets `net8.0` and references the `Microsoft.AspNetCore.App` shared framework, so use it from an ASP.NET Core app or any .NET 8 project that can reference that framework.

## Quick start

Register the validator in `Program.cs` and use it in an endpoint:

```csharp
using DocuTrust.Core.Abstractions;
using DocuTrust.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDocuTrust();

var app = builder.Build();

app.MapPost("/upload", async (IFormFile file, IDocuTrustFileValidator validator) =>
{
    var result = await validator.ValidateFileAsync(file, ".pdf");
    if (!result.IsValid)
        return Results.BadRequest(result.Message);

    return Results.Ok(new { result.ActualMimeType, result.ActualExtension });
}).DisableAntiforgery();

app.Run();
```

## Usage

All methods are on `IDocuTrustFileValidator` and return a `DocuTrustValidationResult` with `IsValid`, `ActualMimeType`, `ActualExtension` and `Message`. The expected extension works with or without the leading dot.

### Validate an upload

```csharp
var result = await validator.ValidateFileAsync(file, ".docx");
```

Both the bytes and the client file name have to agree with `.docx`. Store the file under a name you generate, not the one the client sent.

### Validate a stream

```csharp
await using var stream = File.OpenRead(path);
var result = await validator.ValidateFileStreamAsync(stream, ".png");
// stream.Position is back where it was, so you can keep reading.
```

### Validate a file on disk

```csharp
var result = await validator.ValidateFilePathAsync("/srv/uploads/3f2a.bin", ".pdf");
```

The path is trusted input. DocuTrust follows symbolic links and does not prevent path traversal, so canonicalize any path that comes from outside and check that it stays inside your upload directory.

### Detect a file type

```csharp
var type = await validator.GetFileTypeAsync(path);
if (type.IsValid)
    Console.WriteLine($"{type.ActualMimeType} (.{type.ActualExtension})");
```

### Handle errors

A file of the wrong type comes back with `IsValid == false`. Exceptions are for input the validator cannot work with:

```csharp
using DocuTrust.Exceptions;

try
{
    var result = await validator.ValidateFilePathAsync(path, ".pdf");
    Console.WriteLine(result.IsValid ? "OK" : result.Message);
}
catch (DocuTrustValidationException ex)
{
    // Null or empty arguments, a missing file, a directory, or a read error.
    // ex.Message is a fixed string; the cause is in ex.InnerException.
    logger.LogWarning(ex.InnerException, "Validation could not run: {Message}", ex.Message);
}
```

A token that is already cancelled produces an `OperationCanceledException`.

### Without dependency injection

```csharp
using DocuTrust.Core.Services;

IDocuTrustFileValidator validator = new DocuTrustFileScanner();
```

## Samples

[samples/BasicUsage](samples/BasicUsage) is a console app that walks through every method above, including the failure cases. Run it from the repository root:

```bash
dotnet run --project samples/BasicUsage
```

More detail is in [docs/](docs).

## Contributing

Issues and pull requests are welcome. Before opening a pull request, build and run the tests:

```bash
dotnet test tests/DocuTrust.UnitTests/DocuTrust.UnitTests.csproj
```

The .NET 8 SDK cannot read `DocuTrust.slnx` (that needs SDK 9.0.200 or later), so build the projects directly. CI runs the same tests and fails on packages with known vulnerabilities. Report security issues privately to the maintainer instead of opening a public issue.

## License

DocuTrust.NET is released under the [MIT License](LICENSE). It depends on [PdfPig](https://github.com/UglyToad/PdfPig) (Apache-2.0), [DocumentFormat.OpenXml](https://github.com/dotnet/Open-XML-SDK) (MIT) and [FileSignatures](https://github.com/neilharvey/FileSignatures) (MIT); see [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).

Built by Saud Saad Al-Rashidi ([sa3od34ki@gmail.com](mailto:sa3od34ki@gmail.com)). Source: https://github.com/saa-999/DocuTrust.NET
