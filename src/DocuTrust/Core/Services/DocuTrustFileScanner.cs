using Microsoft.AspNetCore.Http;
using FileSignatures;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Constants;
using DocuTrust.Core.Models;
using DocuTrust.Exceptions;

namespace DocuTrust.Core.Services;

/// <summary>
/// The default <see cref="IDocuTrustFileValidator"/>. It detects file types from their signatures with the
/// FileSignatures library and compares them to the expected extension.
/// </summary>
/// <remarks>
/// The class holds no per-request state. Resolve it through <see cref="DocuTrust.Extensions.DocuTrustExtensions.AddDocuTrust"/>
/// or create it directly.
/// </remarks>
/// <example>
/// <code>
/// IDocuTrustFileValidator validator = new DocuTrustFileScanner();
/// var result = await validator.ValidateFileStreamAsync(stream, ".png");
/// </code>
/// </example>
public class DocuTrustFileScanner : IDocuTrustFileValidator
{
    private readonly FileFormatInspector _inspector;

    /// <summary>
    /// Creates a validator that recognises the formats built into FileSignatures.
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

            using var fileStream = OpenRegularFile(filePath, out var notRegular);
            if (fileStream == null)
                return Task.FromResult(notRegular!);
            if (OversizedContainer(fileStream, fileStream.Length) is { } tooLarge)
                return Task.FromResult(tooLarge);
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
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Validation failed for the provided path.", ex));
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

        // The inspector seeks to 0 and leaves the stream there; the caller's position is restored afterwards.
        long? originalPosition = fileStream.CanSeek ? fileStream.Position : null;
        try
        {
            if (OversizedContainer(fileStream, fileStream.CanSeek ? fileStream.Length : 0) is { } tooLarge)
                return Task.FromResult(tooLarge);
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
        finally
        {
            if (originalPosition is long position && fileStream.CanSeek)
                fileStream.Position = position;
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


            using var fileStream = OpenRegularFile(filePath, out var notRegular);
            if (fileStream == null)
                return Task.FromResult(notRegular!);
            if (OversizedContainer(fileStream, fileStream.Length) is { } tooLarge)
                return Task.FromResult(tooLarge);

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
            return Task.FromException<DocuTrustValidationResult>(new DocuTrustValidationException("Validation failed for the provided path.", ex));
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
            if (OversizedContainer(fileStream, Math.Max(file.Length, fileStream.CanSeek ? fileStream.Length : 0)) is { } tooLarge)
                return Task.FromResult(tooLarge);

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

                new DocuTrustValidationException("Validation failed for the provided file.", ex)

                );
        }
    }

    /// <summary>
    /// Opens a path for inspection only if it resolves (through symlinks) to a non-empty regular file.
    /// <c>open(2)</c> on a FIFO blocks until a writer appears and reads from character devices may block; .NET 8 has
    /// no FIFO test, but <c>stat</c> reports size 0 for FIFOs, character devices and most <c>/proc</c> entries, so
    /// such targets are refused before opening. Regular files are always seekable, which is re-checked after opening.
    /// Missing files and directories throw (unchanged behaviour). Path traversal, symlink policy and UNC paths remain
    /// the caller's responsibility (see <see cref="IDocuTrustFileValidator"/>).
    /// </summary>
    private static FileStream? OpenRegularFile(string filePath, out DocuTrustValidationResult? rejection)
    {
        rejection = null;
        var info = new FileInfo(filePath);
        var target = info.LinkTarget != null ? info.ResolveLinkTarget(returnFinalTarget: true) ?? info : info;
        if (target is not FileInfo file || !file.Exists)
            throw new FileNotFoundException("The file does not exist or is not a file.");

        var notRegular = new DocuTrustValidationResult { IsValid = false, Message = "[DocuTrust] Validation failed: the path is empty or not a regular file." };
        if (file.Length == 0)
        {
            rejection = notRegular;
            return null;
        }

        var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.None);
        if (!stream.CanSeek)
        {
            stream.Dispose();
            rejection = notRegular;
            return null;
        }
        return stream;
    }

    private static readonly byte[] CompoundFileMagic = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    /// <summary>
    /// FileSignatures parses ZIP (OOXML) and OLE/CFB candidates with ZipArchive and OpenMcdf to tell formats apart,
    /// so those containers are refused above <see cref="FileSize.MaxFileSizeBytes"/> before any parsing. Other
    /// formats only need their header and keep working at any size.
    /// </summary>
    private static DocuTrustValidationResult? OversizedContainer(Stream stream, long length)
    {
        if (length <= FileSize.MaxFileSizeBytes || !stream.CanSeek)
            return null;

        long position = stream.Position;
        Span<byte> header = stackalloc byte[8];
        int read;
        try
        {
            stream.Position = 0;
            read = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
        }
        finally
        {
            stream.Position = position;
        }

        header = header[..read];
        bool container = header.StartsWith("PK"u8) || header.StartsWith(CompoundFileMagic);
        return container
            ? new DocuTrustValidationResult { IsValid = false, Message = "[DocuTrust] Validation failed: container file exceeds the size limit for format inspection." }
            : null;
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
