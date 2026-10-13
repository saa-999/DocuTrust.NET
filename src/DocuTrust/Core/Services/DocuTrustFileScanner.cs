using Microsoft.AspNetCore.Http;
using FileSignatures;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Models;
using DocuTrust.Exceptions;

namespace DocuTrust.Core.Services;

/// <summary>
/// The heavy lifter for file validation. Checks extensions, signatures, and handles uploads.
/// </summary>
public class DocuTrustFileScanner : IDocuTrustFileValidator
{
    private readonly FileFormatInspector _inspector;

    /// <summary>
    /// Sets up the scanner with a fresh file format inspector.
    /// </summary>
    public DocuTrustFileScanner()
    {
        _inspector = new FileFormatInspector();
    }

    /// <inheritdoc />
    public Task<DocuTrustValidationResult> ValidateFilePathAsync(string filePath, string expectedExtension, CancellationToken token = default)
    {

        if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(expectedExtension))
        {
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Input cannot be null or empty."));
        }

        if (token.IsCancellationRequested)
        {
            return Task.FromCanceled<DocuTrustValidationResult>(token);
        }
         
        try
        {

            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, false  );
            var format = _inspector.DetermineFileFormat(fileStream);

            if (format != null)
            {


                string normalizedExpected = expectedExtension.StartsWith(".") ? expectedExtension[1..] : expectedExtension;
                if (normalizedExpected.Equals(format.Extension, StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(

                        new DocuTrustValidationResult
                        {
                            IsValid = true,
                            ActualMimeType = format.MediaType,
                            ActualExtension = format.Extension,
                            Message = $"[DocuTrust] Validation successful: {format.MediaType} ({format.Extension})."
                        }
                        );
                }



            }


            return Task.FromResult(

                new  DocuTrustValidationResult
                {
                    IsValid = false,
                    ActualMimeType = format?.MediaType,
                    ActualExtension = format?.Extension,
                    Message = "[DocuTrust] Validation failed: Incorrect file format."
                }

                );
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException($"Validation failed for path: {filePath}", ex));
        }
    }

    /// <inheritdoc />
    public  Task<DocuTrustValidationResult> ValidateFileStreamAsync(Stream fileStream, string expectedExtension , CancellationToken token)
    {

        if (fileStream == null || string.IsNullOrEmpty(expectedExtension))
        {
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Input cannot be null or empty."));
        }
            
            if (token.IsCancellationRequested)
            {
                return Task.FromCanceled<DocuTrustValidationResult>(token);
             }
        try
        {
            
            var format = _inspector.DetermineFileFormat(fileStream);

            if (format != null)
            {
             
                string normalizedExpected = expectedExtension.StartsWith(".") ? expectedExtension[1..] : expectedExtension;
                if (normalizedExpected.Equals(format.Extension, StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(

                        new DocuTrustValidationResult
                        {
                            IsValid = true,
                            ActualMimeType = format.MediaType,
                            ActualExtension = format.Extension,
                            Message = $"[DocuTrust] Validation successful: {format.MediaType} ({format.Extension})."
                        }


                        );
                }

            }




            return Task.FromResult(

                 new DocuTrustValidationResult
                 {
                     IsValid = false,
                     ActualMimeType = format?.MediaType,
                     ActualExtension = format?.Extension,
                     Message = "[DocuTrust] Validation failed: Incorrect file format."
                 }



                );
        }
        catch (Exception ex) when(ex is not OperationCanceledException)
        {
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Validation failed for the provided stream.", ex));
        }
    }

    /// <inheritdoc />
    public  Task<DocuTrustValidationResult> GetFileTypeAsync(string filePath , CancellationToken token=default)
    {
        if (string.IsNullOrEmpty(filePath))
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Input path cannot be null or empty."));

        if (token.IsCancellationRequested)
            return Task.FromCanceled<DocuTrustValidationResult>(token);


        try
        {


            using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, false);

            var format = _inspector.DetermineFileFormat(fileStream);

            if (format != null)
            {
                return Task.FromResult(

                     new DocuTrustValidationResult
                     {
                         IsValid = true,
                         ActualMimeType = format.MediaType,
                         ActualExtension = format.Extension,
                         Message = $"[DocuTrust] Validation successful: {format.MediaType} ({format.Extension})."
                     }


                    );

            }

            return Task.FromResult(

                 new DocuTrustValidationResult
                 {
                     IsValid = false,
                     Message = "[DocuTrust] Validation failed: Could not determine file format."
                 }


                );
        }
        catch (Exception ex) when(ex is not OperationCanceledException)
        {
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException($"Validation failed for path: {filePath}", ex));
        }

    }

    /// <inheritdoc />
    public  Task<DocuTrustValidationResult> ValidateFileAsync(IFormFile file, string expectedExtension , CancellationToken token=default)
    {
        if (file == null)
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Input file cannot be null."));

        if (file.Length == 0)
            return Task.FromResult(

                new DocuTrustValidationResult { IsValid = false, Message = "[DocuTrust] Validation failed: The provided file is empty." }

                );
        if (token.IsCancellationRequested)
            return Task.FromCanceled<DocuTrustValidationResult>(token);

        try
        {
           
            using var fileStream = file.OpenReadStream();

            var format = _inspector.DetermineFileFormat(fileStream);

            // Fail closed: without an expected type there is nothing to validate against, and "any recognised
            // format" includes executables. The detection result is still reported for callers that need it.
            if (string.IsNullOrWhiteSpace(expectedExtension) || expectedExtension.Trim() == ".")
            {
                return Task.FromResult(new DocuTrustValidationResult
                {
                    IsValid = false,
                    ActualMimeType = format?.MediaType,
                    ActualExtension = format?.Extension,
                    Message = "[DocuTrust] Validation failed: an expected extension is required."
                });
            }

            if (format != null)
            {
                string normalizedExpected = expectedExtension.StartsWith(".") ? expectedExtension[1..] : expectedExtension;
                if (normalizedExpected.Equals(format.Extension, StringComparison.OrdinalIgnoreCase))
                {
                    // The bytes match; the client-supplied name must not claim a different (e.g. executable or
                    // script) type, because applications often store or serve files under that name.
                    var nameProblem = CheckClientFileName(file.FileName, normalizedExpected);
                    if (nameProblem != null)
                    {
                        return Task.FromResult(new DocuTrustValidationResult
                        {
                            IsValid = false,
                            ActualMimeType = format.MediaType,
                            ActualExtension = format.Extension,
                            Message = nameProblem
                        });
                    }

                    return Task.FromResult(new DocuTrustValidationResult
                    {
                        IsValid = true,
                        ActualMimeType = format.MediaType,
                        ActualExtension = format.Extension,
                        Message = $"[DocuTrust] Validation successful: {format.MediaType} ({format.Extension})."
                    });
                }
            }

            return Task.FromResult(


                new DocuTrustValidationResult
                {
                    IsValid = false,
                    ActualMimeType = format?.MediaType,
                    ActualExtension = format?.Extension,
                    Message = "[DocuTrust] Validation failed: Incorrect file format."
                }


                );
        }
        catch (Exception ex) when(ex is not OperationCanceledException)
        {
            return Task.FromException<DocuTrustValidationResult>(

                new DocuTrustValidationException($"Validation failed for file: {file.FileName}", ex)

                );
        }
    }

    private static readonly string[][] ExtensionAliases =
    [
        ["jpg", "jpeg", "jpe", "jfif"],
        ["tif", "tiff"],
        ["htm", "html"],
        ["mpg", "mpeg"],
    ];

    /// <summary>
    /// Validates the client-supplied file name against the expected extension. Returns a constant failure message,
    /// or null when the name is acceptable. A name without an extension (e.g. "blob") is accepted.
    /// </summary>
    internal static string? CheckClientFileName(string? fileName, string expectedExtension)
    {
        if (string.IsNullOrEmpty(fileName))
            return null;

        // Old browsers send a full client path; only the last segment is the name.
        var name = fileName[(fileName.LastIndexOfAny(['/', '\\']) + 1)..];

        // Control characters (including NUL truncation) and ':' (NTFS alternate data streams, "evil.asp:.pdf")
        // make the stored name differ from the one validated here.
        if (name.Any(c => char.IsControl(c) || c == ':'))
            return "[DocuTrust] Validation failed: the file name contains characters that are not allowed.";

        // Windows drops trailing dots and spaces: "evil.html." is saved as "evil.html".
        name = name.TrimEnd('.', ' ');
        var extension = Path.GetExtension(name);
        if (extension.Length <= 1)
            return null;

        return SameExtension(extension[1..], expectedExtension)
            ? null
            : "[DocuTrust] Validation failed: the file name extension does not match the expected type.";
    }

    private static bool SameExtension(string actual, string expected)
    {
        if (actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            return true;
        return ExtensionAliases.Any(group =>
            group.Contains(actual, StringComparer.OrdinalIgnoreCase) && group.Contains(expected, StringComparer.OrdinalIgnoreCase));
    }
}
