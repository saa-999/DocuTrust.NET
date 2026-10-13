using Microsoft.Extensions.DependencyInjection;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Services;

namespace DocuTrust.Extensions;

/// <summary>
/// Registers DocuTrust services with an <see cref="IServiceCollection"/>.
/// </summary>
public static class DocuTrustExtensions
{
    /// <summary>
    /// Registers <see cref="IDocuTrustFileValidator"/> (implemented by <see cref="DocuTrustFileScanner"/>) and the
    /// internal PDF and Office scanners, all with a scoped lifetime.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <example>
    /// <code>
    /// var builder = WebApplication.CreateBuilder(args);
    /// builder.Services.AddDocuTrust();
    /// </code>
    /// </example>
    public static IServiceCollection AddDocuTrust(this IServiceCollection services)
    {
        services.AddScoped<IDocuTrustFileValidator, DocuTrustFileScanner>();
        services.AddScoped<DocuTrustPdfScanner>();
        services.AddScoped<DocuTrustOfficeScanner>();

        return services;
    }
}
