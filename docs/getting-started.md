# Getting Started with DocuTrust.NET

## Prerequisites

- .NET 8.0 SDK or later
- Visual Studio 2022 or VS Code

## Installation

```bash
NONE
```

*(Note: During this early release phase, please reference the project directly or copy the source into your solution.)*

## Your First Validation

Here's how to quickly validate an uploaded file in an ASP.NET Core Controller:

```csharp
using Microsoft.AspNetCore.Mvc;
using DocuTrust.Core.Abstractions;

[ApiController]
[Route("api/[controller]")]
public class UploadController : ControllerBase
{
    private readonly IDocuTrustFileValidator _validator;

    public UploadController(IDocuTrustFileValidator validator)
    {
        _validator = validator;
    }

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        // This checks both the extension AND the magic bytes
        var result = await _validator.ValidateFileAsync(file, ".pdf");

        if (!result.IsValid)
        {
            return BadRequest(result.Message);
        }

        return Ok("File is valid!");
    }
}
```

## Registering Services

In your `Program.cs`, simply add:

```csharp
using DocuTrust.Extensions;

builder.Services.AddDocuTrust();
```