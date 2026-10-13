using System.Text;

namespace DocuTrust.Tests.TestSupport;

/// <summary>Hand-written minimal PDFs. Scripts are benign markers such as app.alert(1).</summary>
internal static class PdfFixtures
{
    /// <summary>
    /// Builds a PDF from numbered object bodies (object 1 must be the catalog) with a correct xref table.
    /// </summary>
    public static byte[] Build(IReadOnlyList<string> objects, string? trailerExtra = null, string? appendAfterEof = null)
    {
        var sb = new StringBuilder("%PDF-1.7\n%âãÏÓ\n");
        var offsets = new List<int>();
        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(Encoding.Latin1.GetByteCount(sb.ToString()));
            sb.Append($"{i + 1} 0 obj\n{objects[i]}\nendobj\n");
        }
        int xref = Encoding.Latin1.GetByteCount(sb.ToString());
        sb.Append($"xref\n0 {objects.Count + 1}\n0000000000 65535 f \n");
        foreach (var offset in offsets)
            sb.Append($"{offset:D10} 00000 n \n");
        sb.Append($"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R {trailerExtra} >>\nstartxref\n{xref}\n%%EOF\n");
        sb.Append(appendAfterEof);
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    /// <summary>Catalog with one empty page; <paramref name="catalogExtra"/> is spliced into the catalog dictionary.</summary>
    public static byte[] WithCatalog(string catalogExtra, params string[] extraObjects)
    {
        var objects = new List<string>
        {
            $"<< /Type /Catalog /Pages 2 0 R {catalogExtra} >>",
            "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        };
        objects.AddRange(extraObjects);
        return Build(objects);
    }

    /// <summary>Like <see cref="WithCatalog"/> but <paramref name="pageExtra"/> is spliced into the page dictionary.</summary>
    public static byte[] WithPage(string pageExtra, params string[] extraObjects)
    {
        var objects = new List<string>
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] {pageExtra} >>",
        };
        objects.AddRange(extraObjects);
        return Build(objects);
    }

    /// <summary>
    /// Builds a PDF 1.5 file whose <paramref name="compressed"/> objects live inside an (unfiltered) object stream,
    /// referenced from a cross-reference stream. Plain objects are numbered 1..P (object 1 is the catalog), the
    /// object stream is P+1 and compressed objects are P+2 onwards. Stream bodies are invisible to the raw scan,
    /// so anything found in compressed objects proves the structural walk.
    /// </summary>
    public static byte[] BuildWithObjectStream(IReadOnlyList<string> plain, IReadOnlyList<string> compressed)
    {
        var file = new MemoryStream();
        void Write(string text) => file.Write(Encoding.Latin1.GetBytes(text));

        Write("%PDF-1.7\n%\u00E2\u00E3\u00CF\u00D3\n");
        var offsets = new List<long>();
        for (int i = 0; i < plain.Count; i++)
        {
            offsets.Add(file.Length);
            Write($"{i + 1} 0 obj\n{plain[i]}\nendobj\n");
        }

        int streamNumber = plain.Count + 1;
        var header = new StringBuilder();
        var bodies = new StringBuilder();
        for (int j = 0; j < compressed.Count; j++)
        {
            header.Append($"{streamNumber + 1 + j} {bodies.Length} ");
            bodies.Append(compressed[j]).Append('\n');
        }
        string objStmData = header.ToString() + bodies;
        offsets.Add(file.Length);
        Write($"{streamNumber} 0 obj\n<< /Type /ObjStm /N {compressed.Count} /First {header.Length} /Length {objStmData.Length} >>\nstream\n{objStmData}\nendstream\nendobj\n");

        int xrefNumber = streamNumber + compressed.Count + 1;
        var rows = new MemoryStream();
        void Row(byte type, long field2, int field3)
        {
            rows.WriteByte(type);
            for (int shift = 24; shift >= 0; shift -= 8) rows.WriteByte((byte)(field2 >> shift));
            rows.WriteByte((byte)(field3 >> 8));
            rows.WriteByte((byte)field3);
        }
        Row(0, 0, 0xFFFF);
        for (int i = 0; i < plain.Count; i++) Row(1, offsets[i], 0);
        Row(1, offsets[plain.Count], 0);
        for (int j = 0; j < compressed.Count; j++) Row(2, streamNumber, j);
        long xrefOffset = file.Length;
        Row(1, xrefOffset, 0);

        var rowBytes = rows.ToArray();
        Write($"{xrefNumber} 0 obj\n<< /Type /XRef /Size {xrefNumber + 1} /W [1 4 2] /Root 1 0 R /Length {rowBytes.Length} >>\nstream\n");
        file.Write(rowBytes);
        Write($"\nendstream\nendobj\nstartxref\n{xrefOffset}\n%%EOF\n");
        return file.ToArray();
    }
}
