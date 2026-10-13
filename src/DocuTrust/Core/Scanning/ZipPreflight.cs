using System.Buffers;
using System.Buffers.Binary;

namespace DocuTrust.Core.Scanning;

/// <summary>
/// Counts central-directory records before <see cref="System.IO.Compression.ZipArchive"/> materialises them.
/// ZipArchive reads every record until the signature stops matching and only then compares with the declared
/// count, so a small file with millions of records would allocate millions of entry objects first.
/// </summary>
internal static class ZipPreflight
{
    private const uint EndOfCentralDirectorySignature = 0x06054b50;
    private const uint Zip64LocatorSignature = 0x07064b50;
    private const uint Zip64EndOfCentralDirectorySignature = 0x06064b50;
    private const uint CentralHeaderSignature = 0x02014b50;
    private const int EndOfCentralDirectorySize = 22;
    private const int Zip64LocatorSize = 20;
    private const int Zip64EndOfCentralDirectorySize = 56;
    private const int CentralHeaderSize = 46;

    /// <summary>Returns a safe threat message when the archive is malformed or has too many entries; otherwise null.</summary>
    public static string? Check(Stream stream, int maxEntries, ArrayPool<byte> pool, CancellationToken token)
    {
        long length = stream.Length;
        if (length < EndOfCentralDirectorySize)
            return Malformed;

        int tailLength = (int)Math.Min(length, EndOfCentralDirectorySize + ushort.MaxValue);
        long tailStart = length - tailLength;
        byte[] tail = pool.Rent(tailLength);
        try
        {
            stream.Position = tailStart;
            stream.ReadExactly(tail, 0, tailLength);

            // Same rule as ZipArchive: the record closest to the end of the file wins.
            int eocd = -1;
            for (int i = tailLength - EndOfCentralDirectorySize; i >= 0; i--)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(i)) == EndOfCentralDirectorySignature)
                {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0)
                return Malformed;

            long declaredEntries = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(eocd + 10));
            long centralDirectoryOffset = BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(eocd + 16));
            bool zip64 = declaredEntries == ushort.MaxValue
                || centralDirectoryOffset == uint.MaxValue
                || BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(eocd + 4)) == ushort.MaxValue;

            if (zip64)
            {
                long locatorPosition = tailStart + eocd - Zip64LocatorSize;
                if (locatorPosition < 0)
                    return Malformed;

                Span<byte> locator = stackalloc byte[Zip64LocatorSize];
                stream.Position = locatorPosition;
                stream.ReadExactly(locator);
                if (BinaryPrimitives.ReadUInt32LittleEndian(locator) != Zip64LocatorSignature)
                    return Malformed;

                ulong recordPosition = BinaryPrimitives.ReadUInt64LittleEndian(locator[8..]);
                if (recordPosition > (ulong)(length - Zip64EndOfCentralDirectorySize))
                    return Malformed;

                Span<byte> record = stackalloc byte[Zip64EndOfCentralDirectorySize];
                stream.Position = (long)recordPosition;
                stream.ReadExactly(record);
                if (BinaryPrimitives.ReadUInt32LittleEndian(record) != Zip64EndOfCentralDirectorySignature)
                    return Malformed;

                ulong entries64 = BinaryPrimitives.ReadUInt64LittleEndian(record[32..]);
                ulong offset64 = BinaryPrimitives.ReadUInt64LittleEndian(record[48..]);
                if (entries64 > (ulong)maxEntries)
                    return TooManyEntries;
                if (offset64 > (ulong)length)
                    return Malformed;
                declaredEntries = (long)entries64;
                centralDirectoryOffset = (long)offset64;
            }

            if (declaredEntries > maxEntries)
                return TooManyEntries;
            if (centralDirectoryOffset > length)
                return Malformed;

            // Walk the records exactly as ZipArchive does: until the signature no longer matches.
            Span<byte> header = stackalloc byte[CentralHeaderSize];
            long position = centralDirectoryOffset;
            long count = 0;
            while (position <= length - CentralHeaderSize)
            {
                if ((count & 0xFFF) == 0)
                    token.ThrowIfCancellationRequested();

                stream.Position = position;
                stream.ReadExactly(header);
                if (BinaryPrimitives.ReadUInt32LittleEndian(header) != CentralHeaderSignature)
                    break;

                if (++count > maxEntries)
                    return TooManyEntries;

                position += CentralHeaderSize
                    + BinaryPrimitives.ReadUInt16LittleEndian(header[28..])
                    + BinaryPrimitives.ReadUInt16LittleEndian(header[30..])
                    + BinaryPrimitives.ReadUInt16LittleEndian(header[32..]);
            }

            return null;
        }
        finally
        {
            pool.Return(tail, clearArray: true);
        }
    }

    private const string Malformed = "Package is not a well-formed ZIP archive.";

    private const string TooManyEntries = "Package contains excessive number of parts.";
}
