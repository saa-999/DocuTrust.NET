# DocuTrust.NET 🛡️
### Accelerate your .NET file handling with confidence.

<p align="center">
  <img src="src/DocuTrust/DocuTrust/Header DocuTrust 2.webp" width="600" alt="DocuTrust.NET Logo" />
</p>
![License](https://img.shields.io/badge/License-Attribution%201.0-blue.svg)
![.NET Version](https://img.shields.io/badge/.NET-8.0-purple.svg)
[![NuGet](https://img.shields.io/nuget/v/DocuTrust.NET.svg)](https://www.nuget.org/packages/DocuTrust.NET/)

## Why DocuTrust.NET?

> Every time I started a new .NET project, I found myself wiring up the same libraries — PDF reading, Word documents, file validation. After doing this twice in real projects, I decided to wrap them into a single cohesive library so I (and others) never have to repeat that setup again.

Built by **Saud Saad Al-Rashidi**, a Health Informatics student at SEU, DocuTrust.NET is born from real-world requirements to simplify file security and content extraction.

## Features

- **File Signature Validation:** Verify files by magic bytes, not just extensions.
- **Hardened PDF Scanning:** Deep behavioral analysis to detect embedded JavaScript and malicious structural anomalies.
- **Office Document Intelligence:** Scan both modern (OpenXML) and legacy (OLE) Word, Excel, and PowerPoint files for VBA macros, DDE fields, and suspicious external links.
- **Content Extraction:** Easy-to-use API for pulling text out of PDFs and Office documents.
- **ASP.NET Core Ready:** Seamless dependency injection integration.

## Installation

```bash
dotnet add package DocuTrust.NET
```


## Quick Start

```csharp
using DocuTrust.Extensions;
using DocuTrust.Core.Abstractions;

// 1. Register in Program.cs
builder.Services.AddDocuTrust();

// 2. Inject and Use
public class MyService(IDocuTrustFileValidator validator)
{
    public async Task CheckFile(IFormFile file)
    {
        var result = await validator.ValidateFileAsync(file, ".pdf");
        if (result.IsValid)
        {
            Console.WriteLine($"Validated: {result.ActualMimeType}");
        }
    }
}
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Usage Guide](docs/usage-guide.md)
- [API Reference](docs/api-reference.md)
- [Design Philosophy](docs/why-docutrust.md)

## Dependencies

- [UglyToad.PdfPig](https://github.com/UglyToad/PdfPig)
- [DocumentFormat.OpenXml](https://github.com/dotnet/Open-XML-SDK)
- [FileSignatures](https://github.com/neilharvey/FileSignatures)

## License

DocuTrust.NET is licensed under the **DocuTrust Open Attribution License v1.0**. 
Commercial use is permitted, provided that attribution is given:
> Uses DocuTrust.NET by sa3od34ki@gmail.com

## Contact

Developed by **Saud Saad Al-Rashidi**  
Email: [sa3od34ki@gmail.com](mailto:sa3od34ki@gmail.com)
