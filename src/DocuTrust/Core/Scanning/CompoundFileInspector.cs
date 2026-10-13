using System.Buffers.Binary;
using System.Text;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// Minimal, bounded reader for the Compound File Binary (CFB/OLE) format, used only to tell whether a legacy
/// Office document is encrypted. Every sector and directory chain is followed with a visited set and a hard
/// iteration cap, so a crafted file with a cycle cannot loop (the OpenMcdf CVE class). Any structural oddity
/// makes the inspection return <see cref="CompoundFileVerdict.Unreadable"/> and the caller falls back to the
/// raw heuristic scan — it never reports a verdict it could not establish.
/// </summary>
internal static class CompoundFileInspector
{
    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint FreeSector = 0xFFFFFFFF;
    private const int DirectoryEntrySize = 128;
    private const int MaxSectors = 1 << 20;        // caps a ~4 GB file at 4 KB sectors; well beyond our size limits
    private const int MaxDirectoryEntries = 1 << 16;

    public static CompoundFileVerdict Inspect(Stream stream)
    {
        if (!stream.CanSeek)
            return CompoundFileVerdict.Unreadable;

        try
        {
            return InspectCore(stream);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return CompoundFileVerdict.Unreadable;
        }
    }

    private static CompoundFileVerdict InspectCore(Stream stream)
    {
        long fileLength = stream.Length;
        var header = new byte[512];
        stream.Position = 0;
        if (stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) < header.Length)
            return CompoundFileVerdict.Unreadable;

        int sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(30));
        int miniSectorShift = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(32));
        if (sectorShift is not (9 or 12) || miniSectorShift != 6)
            return CompoundFileVerdict.Unreadable;

        int sectorSize = 1 << sectorShift;
        int miniSectorSize = 1 << miniSectorShift;
        uint firstDirectorySector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(48));
        long miniCutoff = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(56));
        uint firstMiniFatSector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(60));

        var fat = ReadFat(stream, header, sectorSize, fileLength);
        if (fat == null)
            return CompoundFileVerdict.Unreadable;

        var directory = ReadChain(stream, fat, firstDirectorySector, sectorSize, fileLength);
        if (directory == null)
            return CompoundFileVerdict.Unreadable;

        var entries = ParseDirectory(directory);
        if (entries.Count == 0)
            return CompoundFileVerdict.Unreadable;

        // Encrypted OOXML (password-protected .docx/.xlsx/.pptx) is a CFB with these streams.
        if (entries.Any(e => e.Name is "EncryptedPackage" or "EncryptionInfo"))
            return CompoundFileVerdict.Encrypted;

        // Mini stream (root entry's chain) holds streams smaller than the cutoff.
        var root = entries[0];
        var miniFat = ReadMiniFat(stream, fat, firstMiniFatSector, sectorSize, fileLength);
        var miniStream = new Lazy<byte[]?>(() => miniFat == null ? null : ReadChain(stream, fat, root.StartSector, sectorSize, fileLength));

        byte[]? Read(CfbEntry entry, int maxBytes)
        {
            long size = (long)Math.Min(entry.Size, (ulong)fileLength);
            if (size == 0)
                return Array.Empty<byte>();

            byte[]? data;
            if (size >= miniCutoff)
            {
                data = ReadChain(stream, fat, entry.StartSector, sectorSize, fileLength);
            }
            else
            {
                if (miniFat == null || miniStream.Value == null)
                    return null;
                data = ReadMiniChain(miniStream.Value, miniFat, entry.StartSector, miniSectorSize);
            }

            return data?.AsSpan(0, (int)Math.Min(Math.Min(size, data.Length), maxBytes)).ToArray();
        }

        foreach (var entry in entries)
        {
            switch (entry.Name)
            {
                case "WordDocument" when IsEncryptedWord(Read(entry, 16)):
                case "Workbook" or "Book" when IsEncryptedExcel(Read(entry, 4096)):
                case "Current User" when IsEncryptedPowerPoint(Read(entry, 64)):
                    return CompoundFileVerdict.Encrypted;
            }
        }

        return CompoundFileVerdict.NotEncrypted;
    }

    // Word: FibBase is wIdent, nFib, unused, lid, pnNext (2 bytes each) then a uint16 bit field at offset 10;
    // fEncrypted is bit 8 of that field (MS-DOC §2.5.2).
    private static bool IsEncryptedWord(byte[]? fib)
        => fib is { Length: >= 12 }
           && BinaryPrimitives.ReadUInt16LittleEndian(fib.AsSpan(0)) == 0xA5EC
           && (BinaryPrimitives.ReadUInt16LittleEndian(fib.AsSpan(10)) & 0x0100) != 0;

    // Excel: a FILEPASS record (type 0x002F) among the first records means the workbook is encrypted (MS-XLS §2.4.117).
    private static bool IsEncryptedExcel(byte[]? book)
    {
        if (book is not { Length: >= 4 } || BinaryPrimitives.ReadUInt16LittleEndian(book) != 0x0809)
            return false;

        int offset = 0;
        for (int records = 0; records < 16 && offset + 4 <= book.Length; records++)
        {
            ushort type = BinaryPrimitives.ReadUInt16LittleEndian(book.AsSpan(offset));
            ushort size = BinaryPrimitives.ReadUInt16LittleEndian(book.AsSpan(offset + 2));
            if (type == 0x002F)
                return true;
            offset += 4 + size;
        }
        return false;
    }

    // PowerPoint: CurrentUserAtom is an 8-byte record header, a 4-byte size, then headerToken;
    // 0xF3D1C4DF means not encrypted, 0xE391C05F means encrypted (MS-PPT §2.3.2).
    private static bool IsEncryptedPowerPoint(byte[]? currentUser)
        => currentUser is { Length: >= 16 } && BinaryPrimitives.ReadUInt32LittleEndian(currentUser.AsSpan(12)) == 0xE391C05F;

    private static uint[]? ReadFat(Stream stream, byte[] header, int sectorSize, long fileLength)
    {
        var fatSectors = new List<uint>();
        for (int i = 0; i < 109; i++)
        {
            uint sector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(76 + i * 4));
            if (sector == FreeSector)
                break;
            fatSectors.Add(sector);
        }

        // DIFAT sectors (for files with more than 109 FAT sectors) are followed with a visited guard.
        uint difat = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(68));
        var visitedDifat = new HashSet<uint>();
        int perSector = sectorSize / 4;
        while (difat != EndOfChain && difat != FreeSector && visitedDifat.Add(difat))
        {
            if (visitedDifat.Count > MaxSectors)
                return null;
            var sector = ReadSector(stream, difat, sectorSize, fileLength);
            if (sector == null)
                return null;
            for (int i = 0; i < perSector - 1; i++)
            {
                uint entry = BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan(i * 4));
                if (entry != FreeSector)
                    fatSectors.Add(entry);
            }
            difat = BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan((perSector - 1) * 4));
        }

        var fat = new List<uint>();
        foreach (var fatSector in fatSectors)
        {
            var sector = ReadSector(stream, fatSector, sectorSize, fileLength);
            if (sector == null)
                return null;
            for (int i = 0; i < perSector; i++)
                fat.Add(BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan(i * 4)));
            if (fat.Count > MaxSectors)
                return null;
        }
        return fat.ToArray();
    }

    private static uint[]? ReadMiniFat(Stream stream, uint[] fat, uint firstMiniFatSector, int sectorSize, long fileLength)
    {
        var bytes = ReadChain(stream, fat, firstMiniFatSector, sectorSize, fileLength);
        if (bytes == null)
            return null;
        var miniFat = new uint[bytes.Length / 4];
        for (int i = 0; i < miniFat.Length; i++)
            miniFat[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * 4));
        return miniFat;
    }

    private static byte[]? ReadChain(Stream stream, uint[] fat, uint start, int sectorSize, long fileLength)
    {
        using var buffer = new MemoryStream();
        var visited = new HashSet<uint>();
        uint sector = start;
        while (sector != EndOfChain && sector != FreeSector)
        {
            if (sector >= fat.Length || !visited.Add(sector) || visited.Count > MaxSectors)
                return null;
            var bytes = ReadSector(stream, sector, sectorSize, fileLength);
            if (bytes == null)
                return null;
            buffer.Write(bytes);
            sector = fat[sector];
        }
        return buffer.ToArray();
    }

    private static byte[]? ReadMiniChain(byte[] miniStream, uint[] miniFat, uint start, int miniSectorSize)
    {
        using var buffer = new MemoryStream();
        var visited = new HashSet<uint>();
        uint sector = start;
        while (sector != EndOfChain && sector != FreeSector)
        {
            long offset = (long)sector * miniSectorSize;
            if (sector >= miniFat.Length || offset + miniSectorSize > miniStream.Length || !visited.Add(sector) || visited.Count > MaxSectors)
                return null;
            buffer.Write(miniStream.AsSpan((int)offset, miniSectorSize));
            sector = miniFat[sector];
        }
        return buffer.ToArray();
    }

    private static byte[]? ReadSector(Stream stream, uint sector, int sectorSize, long fileLength)
    {
        long offset = (long)(sector + 1) * sectorSize;
        if (offset < 0 || offset + sectorSize > fileLength)
            return null;
        var bytes = new byte[sectorSize];
        stream.Position = offset;
        return stream.ReadAtLeast(bytes, sectorSize, throwOnEndOfStream: false) == sectorSize ? bytes : null;
    }

    private static List<CfbEntry> ParseDirectory(byte[] directory)
    {
        var entries = new List<CfbEntry>();
        int count = Math.Min(directory.Length / DirectoryEntrySize, MaxDirectoryEntries);
        for (int i = 0; i < count; i++)
        {
            int baseOffset = i * DirectoryEntrySize;
            byte objectType = directory[baseOffset + 66];
            if (objectType is not (1 or 2 or 5))
                continue;

            int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(directory.AsSpan(baseOffset + 64));
            if (nameLength is < 2 or > 64)
                continue;

            string name = Encoding.Unicode.GetString(directory.AsSpan(baseOffset, nameLength - 2));
            uint startSector = BinaryPrimitives.ReadUInt32LittleEndian(directory.AsSpan(baseOffset + 116));
            ulong size = BinaryPrimitives.ReadUInt64LittleEndian(directory.AsSpan(baseOffset + 120));
            entries.Add(new CfbEntry(name, startSector, size));
        }
        return entries;
    }

    private readonly record struct CfbEntry(string Name, uint StartSector, ulong Size);
}

internal enum CompoundFileVerdict
{
    Unreadable,
    NotEncrypted,
    Encrypted,
}
