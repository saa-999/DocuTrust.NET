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

            if (string.IsNullOrEmpty(expectedExtension))
            {

                if (format == null)
                    return Task.FromResult(

                         new DocuTrustValidationResult { IsValid = false, Message = "[DocuTrust] Validation failed: Could not determine file format." }


                        );

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
            return Task.FromException<DocuTrustValidationResult>(

                new DocuTrustValidationException($"Validation failed for file: {file.FileName}", ex)

                );
        }
    }
}
