using Microsoft.Extensions.DependencyInjection;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Services;

namespace DocuTrust.Extensions;

/// <summary>
/// Setup helpers to get DocuTrust services into your DI container.
/// </summary>
public static class DocuTrustExtensions
{
    /// <summary>
    /// Hooks up the file validator and scanners to the service collection.
    /// </summary>
    /// <param name="services">DI service collection.</param>
    /// <returns>Chained service collection.</returns>
    public static IServiceCollection AddDocuTrust(this IServiceCollection services)
    {
        services.AddScoped<IDocuTrustFileValidator, DocuTrustFileScanner>();
        services.AddScoped<DocuTrustPdfScanner>();
        services.AddScoped<DocuTrustOfficeScanner>();
        
        return services;
    }
}
