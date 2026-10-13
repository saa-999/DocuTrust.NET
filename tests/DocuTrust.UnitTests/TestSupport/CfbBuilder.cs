using System.Buffers.Binary;
using System.Text;

namespace DocuTrust.Tests.TestSupport;

/// <summary>
/// Writes small, well-formed (acyclic) Compound File Binary v3 files with 512-byte sectors.
/// Streams below 4096 bytes go to the mini stream, larger ones to regular sectors, as the format requires.
/// </summary>
internal sealed class CfbBuilder
{
    private const int SectorSize = 512;
    private const int MiniSectorSize = 64;
    private const int MiniCutoff = 4096;
    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint FreeSector = 0xFFFFFFFF;
    private const uint FatSectorMarker = 0xFFFFFFFD;
    private const uint NoStream = 0xFFFFFFFF;

    private readonly List<(string Name, byte[] Data)> _streams = new();

    public CfbBuilder Stream(string name, byte[] data)
    {
        _streams.Add((name, data));
        return this;
    }

    public byte[] Build()
    {
        // Mini stream: small streams, each padded to whole 64-byte mini sectors.
        var miniStream = new MemoryStream();
        var miniFat = new List<uint>();
        var starts = new uint[_streams.Count];
        for (int i = 0; i < _streams.Count; i++)
        {
            var data = _streams[i].Data;
            if (data.Length >= MiniCutoff || data.Length == 0)
                continue;
            int count = (data.Length + MiniSectorSize - 1) / MiniSectorSize;
            starts[i] = (uint)miniFat.Count;
            for (int s = 0; s < count; s++)
                miniFat.Add(s == count - 1 ? EndOfChain : (uint)(miniFat.Count + 1));
            miniStream.Write(data);
            miniStream.Write(new byte[count * MiniSectorSize - data.Length]);
        }

        int dirSectors = Math.Max(1, ((_streams.Count + 1) * 128 + SectorSize - 1) / SectorSize);
        int miniFatSectors = miniFat.Count == 0 ? 0 : (miniFat.Count * 4 + SectorSize - 1) / SectorSize;
        int miniStreamSectors = (int)((miniStream.Length + SectorSize - 1) / SectorSize);
        var largeSectorCounts = _streams.Select(s => s.Data.Length >= MiniCutoff ? (s.Data.Length + SectorSize - 1) / SectorSize : 0).ToArray();
        int dataSectors = dirSectors + miniFatSectors + miniStreamSectors + largeSectorCounts.Sum();

        int fatSectors = 1;
        while (fatSectors * (SectorSize / 4) < fatSectors + dataSectors)
            fatSectors++;

        int totalSectors = fatSectors + dataSectors;
        var fat = Enumerable.Repeat(FreeSector, fatSectors * (SectorSize / 4)).ToArray();
        int next = 0;

        uint Chain(int count)
        {
            if (count == 0)
                return EndOfChain;
            uint first = (uint)next;
            for (int k = 0; k < count; k++, next++)
                fat[next] = k == count - 1 ? EndOfChain : (uint)(next + 1);
            return first;
        }

        for (int k = 0; k < fatSectors; k++, next++)
            fat[next] = FatSectorMarker;

        uint dirStart = Chain(dirSectors);
        uint miniFatStart = Chain(miniFatSectors);
        uint miniStreamStart = Chain(miniStreamSectors);
        var largeStarts = largeSectorCounts.Select(Chain).ToArray();

        var file = new byte[(totalSectors + 1) * SectorSize];
        WriteHeader(file, fatSectors, dirStart, miniFatStart, miniFatSectors);

        Span<byte> Sector(uint index) => file.AsSpan((int)(index + 1) * SectorSize, SectorSize);

        for (int k = 0; k < fatSectors; k++)
            for (int e = 0; e < SectorSize / 4; e++)
                BinaryPrimitives.WriteUInt32LittleEndian(Sector((uint)k)[(e * 4)..], fat[k * (SectorSize / 4) + e]);

        // Directory: root entry, then one stream entry per stream linked through right siblings.
        var directory = new byte[dirSectors * SectorSize];
        WriteEntry(directory, 0, "Root Entry", 5, NoStream, _streams.Count > 0 ? 1u : NoStream,
            miniStream.Length > 0 ? miniStreamStart : EndOfChain, (ulong)miniStream.Length);
        for (int i = 0; i < _streams.Count; i++)
        {
            var data = _streams[i].Data;
            uint start = data.Length == 0 ? EndOfChain : data.Length >= MiniCutoff ? largeStarts[i] : starts[i];
            WriteEntry(directory, i + 1, _streams[i].Name, 2, i + 1 < _streams.Count ? (uint)(i + 2) : NoStream, NoStream, start, (ulong)data.Length);
        }
        for (int k = 0; k < dirSectors; k++)
            directory.AsSpan(k * SectorSize, SectorSize).CopyTo(Sector(dirStart + (uint)k));

        var miniFatBytes = new byte[miniFatSectors * SectorSize];
        miniFatBytes.AsSpan().Fill(0xFF);
        for (int e = 0; e < miniFat.Count; e++)
            BinaryPrimitives.WriteUInt32LittleEndian(miniFatBytes.AsSpan(e * 4), miniFat[e]);
        for (int k = 0; k < miniFatSectors; k++)
            miniFatBytes.AsSpan(k * SectorSize, SectorSize).CopyTo(Sector(miniFatStart + (uint)k));

        var mini = miniStream.ToArray();
        for (int k = 0; k < miniStreamSectors; k++)
            mini.AsSpan(k * SectorSize, Math.Min(SectorSize, mini.Length - k * SectorSize)).CopyTo(Sector(miniStreamStart + (uint)k));

        for (int i = 0; i < _streams.Count; i++)
        {
            var data = _streams[i].Data;
            for (int k = 0; k < largeSectorCounts[i]; k++)
                data.AsSpan(k * SectorSize, Math.Min(SectorSize, data.Length - k * SectorSize)).CopyTo(Sector(largeStarts[i] + (uint)k));
        }
        return file;
    }

    private static void WriteHeader(byte[] file, int fatSectors, uint dirStart, uint miniFatStart, int miniFatSectors)
    {
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(file, 0);
        var h = file.AsSpan();
        BinaryPrimitives.WriteUInt16LittleEndian(h[24..], 0x003E);
        BinaryPrimitives.WriteUInt16LittleEndian(h[26..], 0x0003);
        BinaryPrimitives.WriteUInt16LittleEndian(h[28..], 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(h[30..], 9);
        BinaryPrimitives.WriteUInt16LittleEndian(h[32..], 6);
        BinaryPrimitives.WriteUInt32LittleEndian(h[44..], (uint)fatSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(h[48..], dirStart);
        BinaryPrimitives.WriteUInt32LittleEndian(h[56..], MiniCutoff);
        BinaryPrimitives.WriteUInt32LittleEndian(h[60..], miniFatSectors == 0 ? EndOfChain : miniFatStart);
        BinaryPrimitives.WriteUInt32LittleEndian(h[64..], (uint)miniFatSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(h[68..], EndOfChain);
        for (int i = 0; i < 109; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(h[(76 + i * 4)..], i < fatSectors ? (uint)i : FreeSector);
    }

    private static void WriteEntry(byte[] directory, int index, string name, byte type, uint right, uint child, uint start, ulong size)
    {
        var e = directory.AsSpan(index * 128, 128);
        var nameBytes = Encoding.Unicode.GetBytes(name);
        nameBytes.CopyTo(e);
        BinaryPrimitives.WriteUInt16LittleEndian(e[64..], (ushort)(nameBytes.Length + 2));
        e[66] = type;
        e[67] = 1; // black
        BinaryPrimitives.WriteUInt32LittleEndian(e[68..], NoStream);
        BinaryPrimitives.WriteUInt32LittleEndian(e[72..], right);
        BinaryPrimitives.WriteUInt32LittleEndian(e[76..], child);
        BinaryPrimitives.WriteUInt32LittleEndian(e[116..], start);
        BinaryPrimitives.WriteUInt64LittleEndian(e[120..], size);
    }
}
