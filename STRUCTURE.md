# Project Structure
src/
└── DocuTrust/
    ├── Abstractions/
    │   ├── IDocuTrustContentFile.cs
    │   └── IDocuTrustFileValidator.cs
    ├── Models/
    │   ├── DocuTrustFileCheckResult.cs
    │   └── DocuTrustValidationResult.cs
    ├── Services/
    │   ├── DocuTrustPdfScanner.cs
    │   ├── DocuTrustOfficeScanner.cs
    │   └── DocuTrustFileScanner.cs
    ├── Extensions/
    │   └── DocuTrustExtensions.cs
    ├── Exceptions/
    │   └── DocuTrustValidationException.cs
    └── DocuTrust.csproj
tests/
└── DocuTrust.UnitTests/
    └── DocuTrust.UnitTests.csproj
