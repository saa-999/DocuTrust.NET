using System.Xml;

namespace DocuTrust.Core.Scanning;

/// <summary>The only way DocuTrust creates XML readers over untrusted content.</summary>
internal static class SafeXml
{
    public static XmlReader Create(Stream stream) => XmlReader.Create(stream, CreateSettings());

    // A fresh instance per reader: XmlReaderSettings is mutable and is not shared across threads.
    internal static XmlReaderSettings CreateSettings() => new()
    {
        // No DTDs at all: rules out XXE, entity expansion ("billion laughs") and external fetches.
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = 0,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        CloseInput = false,
    };
}
