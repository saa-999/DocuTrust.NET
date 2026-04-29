# Why DocuTrust.NET?

## The Problem
As a developer working on health informatics projects at SEU, I found myself repeatedly implementing the same security checks for user uploads:
1. "Is this really a PDF?"
2. "Does this Word document contain malicious macros?"
3. "How do I extract text from this file without a massive overhead?"

After setting up the same combination of `PdfPig`, `OpenXml`, and `FileSignatures` in two separate projects, I realized this boilerplate was a productivity killer.

## The Solution
DocuTrust.NET was built to bundle these powerful libraries into a single, cohesive, and easy-to-use package. Instead of wiring up three different libraries and learning their intricate internals, you can just call `ValidateFileAsync`.

## Design Decisions

### Choosing the Libraries
- **PdfPig:** Chosen for its excellent parsing capabilities and ability to look deep into PDF dictionaries for behavioral analysis.
- **Open-XML-SDK:** The industry standard for handling Microsoft Office files accurately.
- **FileSignatures:** A lightweight and effective way to handle magic byte validation across hundreds of file types.

### Abstraction vs. Access
The library is designed to be "plug-and-play" with ASP.NET Core. While it provides high-level abstractions, it doesn't hide the underlying complexity if you need to perform deep scans — the internal scanners are designed with specialized security logic that handles the heavy lifting so you don't have to.

## Evolution
What started as a set of helper classes in a private repo is now DocuTrust.NET. It has been refined through actual use in real-world scenarios before being prepared for public release.