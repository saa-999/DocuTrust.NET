# DocuTrust.NET — Security Findings Log

- **Audit date:** 2026-10-13
- **Commit audited:** `7cd6c36f23f0ae7eda5393db47bcf93b99c4b1d1` (tag/version `v1.0.2`)
- **Branch with fixes:** `security/audit-2026-10` (local only, nothing pushed)
- **Scope:** `src/DocuTrust/**`, `tests/DocuTrust.UnitTests/**`, `.github/workflows/build.yml`, NuGet dependency graph.

## Baseline

Toolchain: .NET SDK 8.0.131 (Ubuntu 24.04 `dotnet-sdk-8.0` package), runtime 8.0.31.

| Step | Result |
| --- | --- |
| `dotnet restore DocuTrust.slnx` | **Fails**: `MSB4068: The element <Solution> is unrecognized`. `.slnx` needs SDK ≥ 9.0.200, and CI pins `8.0.x` (see DT-038). Projects were restored individually instead. |
| `dotnet restore tests/DocuTrust.UnitTests/DocuTrust.UnitTests.csproj` | OK (restores the library too). |
| `dotnet build` | OK, 0 warnings, 0 errors (`TreatWarningsAsErrors` on). |
| `dotnet test` | **4 passed**, 0 failed, 0 skipped. |
| `dotnet list package --vulnerable --include-transitive` (library) | `OpenMcdf 3.1.0` (transitive via `FileSignatures 7.0.0`), Moderate: GHSA-jxpf-xq2m-q525 (CVE-2026-41511), GHSA-5qwm-7pvp-w988 (CVE-2026-45785). |
| same (test project) | `OpenMcdf 3.1.0` (as above); `System.Net.Http 4.3.0` High (GHSA-7jgj-8wvc-jh57); `System.Text.RegularExpressions 4.3.0` High (GHSA-cmhx-cq75-c4mj). Both come via `xunit 2.6.2 → NETStandard.Library 1.6.1`. |
| `dotnet list package --outdated` (library) | `FileSignatures 7.0.0 → 7.3.0`, `PdfPig 0.1.14 → 0.1.16`. `DocumentFormat.OpenXml 3.5.1` is current. |
| same (test project) | `Microsoft.NET.Test.Sdk 17.8.0 → 18.11.0`, `PdfPig 0.1.14 → 0.1.16`, `xunit 2.6.2 → 2.9.3`, `xunit.runner.visualstudio 2.5.4 → 4.0.1`. |

Empirical probes run before the fixes (scratch program, not committed):

- An `.xlsx` sent to `DocuTrustOfficeScanner.ScanFileContentAsync` is reported as *"Word document is clean."* (DT-014).
- An encrypted PDF with an `/OpenAction` JavaScript returns `IsClean = true` (DT-019).
- .NET 8 `ZipArchive` **does** stop decompression at the declared uncompressed size (a 10 MB entry patched to declare 100 bytes yields 100 bytes). This changes the zip-bomb lead (DT-009).
- PdfPig 0.1.14 decodes `#xx` escapes in names (`/J#61vaScript` → `JavaScript`) (DT-024).
- `FileFormatInspector.DetermineFileFormat` seeks the caller's stream to 0, inspects from offset 0, and leaves it at 0 (DT-032).
- Any upload with the OLE/CFB magic reaches `OpenMcdf` from `ValidateFileAsync` (stack trace `OpenMcdf.Header.set_MiniSectorShift`) (DT-035).

## Summary

| ID | Title | Severity | Status |
| --- | --- | --- | --- |
| DT-001 | Integer overflow in custom pool `Rent` (`1 << 31`) | Low | Fixed |
| DT-002 | Custom pool `Return` accepts arrays of any length | Low | Fixed |
| DT-003 | Pooled buffers holding file contents are never cleared (static pool) | Low | Fixed |
| DT-004 | Custom pool retains up to ~12.8 GB of LOH arrays (memory DoS) | High | Fixed |
| DT-005 | Non-atomic bucket count check-then-add in custom pool | Low | Fixed |
| DT-006 | `(int)stream.Length` narrowing cast; trusts stream length over size check | Medium | Fixed |
| DT-007 | Single non-looped `ReadAsync` leaves the tail of legacy files unscanned | Medium | Fixed |
| DT-008 | Whole-file string decoding (≈3× memory); UTF-16 only at even offsets; `Ole10Native` check dead | Medium | Fixed |
| DT-009 | Zip bomb: no total budget, no ratio limit, CD read before count check, extraction unchecked | High | Fixed |
| DT-010 | Macro detection relies on the part name `vbaProject.bin` only | High | Fixed |
| DT-011 | Embedded payload detection: case-sensitive, incomplete list, no content sniffing, OLE/nested not inspected | High | Fixed |
| DT-012 | DDE detection gaps and fail-open `catch {}` | High | Fixed |
| DT-013 | Relationship analysis gaps and exponential traversal | High | Fixed |
| DT-014 | Every OOXML package is inspected as Word (Excel/PowerPoint branches dead) | Low | Fixed |
| DT-015 | Encrypted Office documents (legacy and CFB-wrapped OOXML) reported clean | High | Fixed |
| DT-016 | Office results echo `ex.Message` and ZIP entry names (disclosure, log injection) | Medium | Fixed |
| DT-017 | Office `GetPageAsync` reports `IsClean = true` without scanning; swallows parse errors | Medium | Fixed |
| DT-018 | Scanners reuse one stream with `Position` resets (non-seekable streams crash) | Low | Fixed |
| DT-019 | Undecryptable encrypted PDFs reported `IsClean = true` | High | Fixed |
| DT-020 | PDF action chain: depth limit fails open; `/Next` arrays ignored | High | Fixed |
| DT-021 | PDF objects that are streams with declared `/Length` > 25 MB are skipped | Medium | Fixed |
| DT-022 | Missing PDF action types, annotation subtypes, form-field `/AA`, URI schemes | High | Fixed |
| DT-023 | PDF objects off the hard-coded paths are never inspected; no raw-byte defense in depth | Medium | Fixed |
| DT-024 | `#xx`-escaped PDF names bypass structural checks | Info | Not an issue |
| DT-025 | PDF `GetPageAsync` reports `IsClean = true` without a threat scan; file parsed 2–3 times | Medium | Open |
| DT-026 | No PDF page-count, glyph or extracted-text limits | Medium | Open |
| DT-027 | PDF/ZIP polyglots not detected | Low | Open |
| DT-028 | PdfPig 0.1.14 has known infinite-recursion (stack overflow) bugs | High | Fixed |
| DT-029 | Empty `expectedExtension` makes `ValidateFileAsync` accept any type, including executables | High | Open |
| DT-030 | Client filename extension ignored (double extensions, docs claim otherwise) | Medium | Open |
| DT-031 | Validator has no size limit before container (ZIP/OLE) parsing | Medium | Open |
| DT-032 | Validator leaves the caller's stream at a changed position | Low | Open |
| DT-033 | Validator exceptions embed the client filename and full path | Low | Open |
| DT-034 | Path APIs block forever on FIFOs/devices; no regular-file checks | Medium | Open |
| DT-035 | Vulnerable `OpenMcdf 3.1.0` (uncatchable infinite loops) reachable from uploads | High | Fixed |
| DT-036 | Vulnerable test-only transitive packages (`System.Net.Http`, `System.Text.RegularExpressions`) | Low | Fixed |
| DT-037 | `FileSize` constants use `int` arithmetic | Info | Open |
| DT-038 | CI never runs tests (and cannot read `.slnx` with SDK 8) | Low | Open |
| DT-039 | No scan time limits | Medium | Open |
| DT-040 | Content scanners are internal; public API only checks magic bytes | Info | Open |
| DT-041 | XML parsing: DTD/XXE settings | Info | Open |
| DT-042 | Thread safety of shared instances (other than the pool) | Info | Open |

---

## Findings

### DT-001 — Integer overflow in custom pool `Rent` (`1 << 31`)
- Severity: Low
- CWE: CWE-190
- Location: src/DocuTrust/Core/Services/DoucTrustMemoryPool.cs:57 (`Rent`)
- Description: `GetBucketIndex` returns 30 for any size in (2^30, 2^31−1], and `1 << (bucketIndex + 1)` is `1 << 31` = `int.MinValue`. `new T[int.MinValue]` throws `OverflowException`. Sizes come from `(int)stream.Length` (DT-006), so any stream whose length is between 1 GiB and 2 GiB crashes the scan.
- Attack scenario / PoC: an `IFormFile` whose `Length` passes the 100 MB check but whose `OpenReadStream().Length` is 1.5 GiB (custom/streaming `IFormFile`) → `Rent(1_610_612_736)` → `OverflowException` → `DocuTrustValidationException` instead of a verdict.
- Fix: Deleted `DoucTrustMemoryPool`/`IMemoryPool`. Buffers come from `ArrayPool<byte>.Shared` via `PooledChunkReader`, which always rents a fixed 64 KB + overlap window, so allocation size no longer depends on any stream length.
- Regression test: OfficeLegacyScanTests.LegacyScan_StreamLengthOutsideIntRange_ReturnsVerdictWithoutOverflow (1.5 GiB and 3 GiB reported lengths)
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-002 — Custom pool `Return` accepts arrays of any length
- Severity: Low
- CWE: CWE-20
- Location: src/DocuTrust/Core/Services/DoucTrustMemoryPool.cs:61-77 (`Return`)
- Description: `Return` buckets by `Log2(length − 1)` without checking that the length equals the bucket's rent size (`2^(b+1)`). A 3-byte array lands in the 4-byte bucket and a later `Rent(4)` returns a 3-byte array. Callers then index past the end (`ReadAsync(buffer, 0, length)` throws). Latent today because only pool-created arrays are returned, but one wrong `Return` corrupts the shared static pool for every request.
- Attack scenario / PoC: not attacker-triggerable in v1.0.2; a maintenance bug would turn into cross-request failures.
- Fix: Custom pool removed; `ArrayPool<byte>.Shared` validates returned arrays itself. `PooledChunkReader` returns exactly the array it rented, once, in `finally`, and never assumes the rented length equals the requested length (all reads and copies use the explicit `capacity`).
- Regression test: BufferPoolTests.Assembly_HasNoCustomMemoryPool; BufferPoolTests.LegacyScan_RentsBoundedBuffers_ReturnsEachOnceCleared (the recording pool hands out oversized arrays and flags foreign returns)
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-003 — Pooled buffers holding file contents are never cleared (static pool)
- Severity: Low
- CWE: CWE-226
- Location: src/DocuTrust/Core/Services/DoucTrustMemoryPool.cs:61-66; DocuTrustOfficeScanner.cs:26, :323, :440
- Description: The pool is a `static` field shared by all scanner instances, and both call sites call `Return(buffer)` with the default `arrayClear = false`. Each request's raw upload bytes stay in pooled arrays for the life of the process and are handed to the next request. Verified: the next request only decodes `[0, bytesRead)`, so the old bytes are not returned in a result today. The lead "leaks to the next request" is therefore not directly observable, but the data remains in memory, crash dumps and heap dumps, and one off-by-one turns it into a cross-tenant disclosure.
- Attack scenario / PoC: process memory dump, or any future code path that uses `buffer.Length` instead of `bytesRead`.
- Fix: Every pooled buffer is returned with `clearArray: true` in a `finally` block (also on exceptions).
- Regression test: BufferPoolTests.LegacyScan_RentsBoundedBuffers_ReturnsEachOnceCleared; BufferPoolTests.LegacyTextExtraction_RentsBoundedBuffers_ReturnsEachOnceCleared; BufferPoolTests.LegacyScan_WhenStreamThrows_StillReturnsBufferCleared
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-004 — Custom pool retains up to ~12.8 GB of LOH arrays (memory DoS)
- Severity: High
- CWE: CWE-770, CWE-401
- Location: src/DocuTrust/Core/Services/DoucTrustMemoryPool.cs:11, :57, :71-76; DocuTrustOfficeScanner.cs:283, :418
- Description: The pool rents whole-file arrays rounded up to the next power of two (a 65 MB file gets a 128 MB array) and keeps up to 50 arrays per bucket forever (no trimming, no GC pressure callback). Buckets up to 2^27 can fill: 50 × (2 + 4 + … + 128 MB) ≈ 12.8 GB of permanently rooted Large Object Heap memory.
- Attack scenario / PoC: 50 concurrent uploads of ~65–100 MB legacy (`D0 CF 11 E0`) files to an endpoint that calls the Office scanner → each rents a 128 MB array → all 50 are returned to the static pool → 6.4 GB retained after the requests finish. Repeat for smaller sizes to fill the other buckets. Even with Kestrel's default 30 MB body limit, ~3.2 GB can be pinned.
- Fix: Whole-file arrays replaced by bounded streaming: one 64 KB (+ keyword overlap, < 80 KB) buffer per scan from `ArrayPool<byte>.Shared`, which is size-bucketed, per-core and trimmed under memory pressure. Nothing is allocated in proportion to the file size.
- Regression test: BufferPoolTests.LegacyScan_RentsBoundedBuffers_ReturnsEachOnceCleared (5 MB file, asserts max rent <= 80 KB)
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-005 — Non-atomic bucket count check-then-add in custom pool
- Severity: Low
- CWE: CWE-362
- Location: src/DocuTrust/Core/Services/DoucTrustMemoryPool.cs:49-52, :71-76
- Description: `Volatile.Read(count) < Max` followed by `Add` then `Interlocked.Increment`, and `TryTake` followed by `Interlocked.Decrement`, are separate operations. Under concurrency the counts drift from the real bag sizes, so the 50-array cap in DT-004 is not a real cap.
- Attack scenario / PoC: concurrent returns overshoot the cap; amplifies DT-004.
- Fix: Custom pool removed; `ArrayPool<byte>.Shared` is thread-safe. No DocuTrust-owned shared mutable state remains.
- Regression test: BufferPoolTests.Assembly_HasNoCustomMemoryPool
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-006 — `(int)stream.Length` narrowing cast; trusts stream length over size check
- Severity: Medium
- CWE: CWE-197, CWE-681
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:281 (`ScanLegacyOfficeAsync`), :417 (`ExtractLegacyTextAsync`)
- Description: The size gate checks `IFormFile.Length`, but the allocation uses `(int)stream.Length`. For lengths ≥ 2^31 the cast wraps to a negative value (`ArgumentOutOfRangeException`), and between 2^30 and 2^31 it hits DT-001. The two lengths can differ for non-`FormFile` implementations, so the 100 MB limit does not bound the allocation.
- Attack scenario / PoC: `IFormFile` with `Length = 10` and a stream reporting 3 GiB → negative rent size → exception; or 1.5 GiB → `OverflowException`.
- Fix: No cast and no use of `stream.Length`. The legacy scan and legacy text extraction count the bytes actually read and fail closed (`IsClean = false`) once `FileSize.MaxFileSizeBytes` is exceeded, whatever `IFormFile.Length` claims.
- Regression test: OfficeLegacyScanTests.LegacyScan_StreamLengthOutsideIntRange_ReturnsVerdictWithoutOverflow; OfficeLegacyScanTests.LegacyScan_StreamLongerThanDeclaredLength_FailsClosed; OfficeLegacyScanTests.LegacyTextExtraction_ShortReads_ReadsEntireFile
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-007 — Single non-looped `ReadAsync` leaves the tail of legacy files unscanned
- Severity: Medium
- CWE: CWE-693 (root cause: short reads not handled, cf. CWE-252)
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:290 (`ScanLegacyOfficeAsync`), :424 (`ExtractLegacyTextAsync`), :42 and :77 (header reads); DocuTrustPdfScanner.cs:147 (header read)
- Description: `Stream.ReadAsync` may return fewer bytes than requested. Only the first read is scanned, so the rest of the file is never searched for macro indicators, and the result is `IsClean = true`.
- Attack scenario / PoC: any `IFormFile` whose stream returns data in pieces (network/streaming implementations) with the VBA indicators placed after the first returned block → legacy scan reports *"Legacy heuristics passed."*.
- Fix: `PooledChunkReader` loops `ReadAsync` until each window is full or the stream ends. Header reads in both scanners use `ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false)`.
- Regression test: OfficeLegacyScanTests.LegacyScan_ShortReads_ScansEntireFile; OfficeLegacyScanTests.LegacyScan_HeaderDeliveredOneByteAtATime_IsRecognised; OfficeLegacyScanTests.LegacyTextExtraction_ShortReads_ReadsEntireFile; DocuTrustPdfScannerTests.ScanFileContentAsync_HeaderDeliveredInSmallReads_IsRecognised
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-008 — Whole-file string decoding (≈3× memory); UTF-16 only at even offsets; `Ole10Native` check dead
- Severity: Medium
- CWE: CWE-400, CWE-693
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:293-319 (`ScanLegacyOfficeAsync`)
- Description: (1) The whole file is decoded into an ASCII string and a UTF-16 string: about 3× the file size in LOH allocations per request (a 100 MB file costs ~300 MB). (2) `Encoding.Unicode.GetString` decodes from offset 0 only, so a UTF-16LE keyword starting at an odd byte offset is invisible. (3) `"\x01Ole10Native"` is searched only in the ASCII view, but OLE stream names are stored UTF-16LE in the CFB directory, so the embedded-OLE check never matches.
- Attack scenario / PoC: a CFB file whose UTF-16LE `AutoOpen` starts at an odd offset → clean. A legacy document with an OLE Package (`\x01Ole10Native`) → clean.
- Fix: New `KeywordSet` matches keywords case-insensitively directly in the raw bytes, both as ASCII and as UTF-16LE at every byte offset (both alignments), with a vectorised first-byte search. No strings are materialised. `\u0001Ole10Native` is part of the set, so its UTF-16 directory name is now found. Windows carry `longest pattern - 1` bytes of overlap so boundary-spanning keywords are found.
- Regression test: OfficeLegacyScanTests.LegacyScan_Utf16KeywordAtOddOffset_IsDetected; OfficeLegacyScanTests.LegacyScan_Ole10NativeDirectoryName_IsDetected; OfficeLegacyScanTests.LegacyScan_KeywordAcrossChunkBoundary_IsDetected (4 cases); OfficeLegacyScanTests.LegacyScan_CleanFile_IsClean
- Status: Fixed
- Commit: Phase 1 commit (`git log --grep "DT-001"`)

### DT-009 — Zip bomb: no total budget, no ratio limit, CD read before count check, extraction unchecked
- Severity: High
- CWE: CWE-409
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:105-126 (`ScanModernOffice`), :329-409 (`ExtractModernText`)
- Description: The lead says the per-entry check relies on the attacker-declared `entry.Length`. Verified: on .NET 8 `ZipArchive` stops inflating at the declared size, so the declared value is an upper bound and the per-entry 20 MB check is effective. The following gaps remain: (1) no total uncompressed budget: 5,000 entries × 20 MB = 100 GB of inflation/XML parsing is allowed, and the DDE/relationship passes parse every `.rels`, header and footer; (2) no compression-ratio limit (a 20 MB run of zeros compresses to ~20 KB); (3) `zip.Entries.Count` materialises the whole central directory before the 5,000-entry check (millions of `ZipArchiveEntry` objects from a 100 MB file); (4) `GetPageAsync` → `ExtractModernText` performs **no** entry checks and loads `Body.InnerText` through the DOM, so a 2 GB `document.xml` compressed to ~2 MB exhausts memory; (5) nested packages in `embeddings/` are not inspected.
- Attack scenario / PoC: a `.docx` whose `word/document.xml` inflates to hundreds of MB, sent to text extraction → OOM. Or many 19 MB zero-filled parts → minutes of CPU per request.
- Fix: New first pass `OfficePackageInspector` streams **every** entry through `BoundedReadStream`, which counts the bytes actually inflated and throws as soon as (a) a part exceeds `MaxPartSizeBytes`, (b) the package exceeds the new shared budget `FileSize.MaxTotalUncompressedBytes` (256 MB), or (c) a part larger than 1 MB exceeds a 100:1 compression ratio. `ZipPreflight` counts central-directory records with fixed-size reads (ZIP64 aware, same walk rule as `ZipArchive`) and rejects more than 5,000 before `ZipArchive` allocates entries. Corrupt deflate data fails closed. Text extraction runs the same pass before the SDK touches a part. Point (5), nested packages, is handled in DT-011.
- Regression test: OfficeZipBombTests.ModernScan_HighlyCompressedPart_FailsClosed; OfficeZipBombTests.ModernScan_TotalDecompressedBudgetExceeded_FailsClosed; OfficeZipBombTests.ModernScan_TooManyEntries_FailsClosed; OfficeZipBombTests.ModernScan_CentralDirectoryLargerThanDeclared_FailsClosedWithoutThrowing; OfficeZipBombTests.TextExtraction_OversizedPart_FailsClosedBeforeDomLoad; OfficeZipBombTests.TextExtraction_HighlyCompressedPart_FailsClosed; OfficeZipBombTests.ModernScan_LargeOrdinaryDocument_IsClean (no false positive)
- Status: Fixed
- Commit: `git log --grep "DT-009"`

### DT-010 — Macro detection relies on the part name `vbaProject.bin` only
- Severity: High
- CWE: CWE-184
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:116-117 (`ScanModernOffice`)
- Description: Office locates the VBA project through the `…/relationships/vbaProject` relationship and the `application/vnd.ms-office.vbaProject` content type, not through the file name. Not checked: renamed VBA parts, `macroEnabled` main content types, `vbaData.xml` (`wordVbaData`), Excel 4.0/XLM macro sheets (`xl/macrosheets/`, `xlMacrosheet`/`xlIntlMacrosheet` relationships, `application/vnd.ms-excel.macrosheet+xml`).
- Attack scenario / PoC: rename `word/vbaProject.bin` to `word/data.bin` and update the relationship target → *"Word document is clean."*. An `.xlsm` whose only payload is an XLM macro sheet → clean.
- Fix: The first pass now flags (a) any content type in `[Content_Types].xml` containing `macroEnabled`, `vbaProject`, `vbaData` (VBA) or `macrosheet` (XLM, incl. `intlmacrosheet`); (b) relationships of type `…/vbaProject`, `…/vbaProjectSignature`, `…/wordVbaData`, `…/xlMacrosheet`, `…/xlIntlMacrosheet` in **every** `.rels` part (case-insensitive); (c) parts named `vbaProject.bin`, `vbaProjectSignature.bin`, `vbaData.xml` or located under `macrosheets/`. Content sniffing of renamed OLE/VBA blobs is added with DT-011.
- Regression test: OfficeMacroDetectionTests (9 tests: literal name, renamed part via relationship, via content type, macro-enabled main type, vbaData by name and by relationship, XLM macro sheet by path, relationship and content type)
- Status: Fixed
- Commit: `git log --grep "DT-010"`

### DT-011 — Embedded payload detection: case-sensitive, incomplete list, no content sniffing, OLE/nested not inspected
- Severity: High
- CWE: CWE-184
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:21-24, :119-124 (`ScanModernOffice`)
- Description: (1) `entry.FullName.Contains("embeddings/")` is case-sensitive (`word/Embeddings/x.exe` passes) and ignores executables stored elsewhere in the package. (2) The extension block-list misses `.hta .lnk .cmd .msi .dll .cpl .pif .reg .iso .scf .sct .chm .xll`, macro-enabled Office types and more. (3) Detection is by extension only: `payload.dat` containing a PE (`MZ`) passes. (4) `oleObject*.bin` (OLE Package / `Ole10Native` carriers, Equation Editor `Equation Native` streams, embedded legacy documents with VBA) are not inspected. (5) Embedded OOXML packages (`.docm` inside `.docx`) are not inspected.
- Attack scenario / PoC: `word/embeddings/oleObject1.bin` = OLE Package wrapping `invoice.exe` → clean.
- Fix: (1) Extension check applies to every part, case-insensitively, after trimming trailing dots/spaces (Windows ignores them). (2) The block-list now covers PE/driver types, installers (`.msi .msix .appx …`), scripts (`.cmd .wsc .ps1/.psm1 .sh …`), `.hta .sct .chm .jar .reg .inf .scf .lnk .url`, shell/search connectors, disk images (`.iso .img .vhd(x)`), `.cab`, `.xll` and all macro-enabled Office types. (3) Every part is classified by its first bytes: PE (`MZ`), ELF, Mach-O/fat/Java class, and Windows shortcut headers are rejected whatever the name. (4) Embedded OLE/CFB blobs (`oleObject*.bin`, embedded `.doc/.xls`) are scanned (ASCII + UTF-16LE) for VBA storages, OLE Package (`\u0001Ole10Native`) and Equation Editor (`Equation Native`) streams. (5) Embedded ZIP/OOXML parts are copied (bounded) and inspected recursively with the same rules and the shared budget, up to `FileSize.MaxNestedPackageDepth` (3); deeper nesting fails closed. The nested copy uses `PooledChunkReader`, not `Stream.CopyToAsync`, whose pooled buffer would go back to the shared pool uncleared.
- Regression test: OfficeEmbeddedPayloadTests (24 cases: capitalised folder, payload outside embeddings, 13 newly blocked extensions incl. trailing dot, PE and ELF headers behind innocent names, OLE Package, Equation Editor, embedded legacy doc with VBA, nested macro-enabled package, payload in plain embedded ZIP, nesting depth, benign embedded workbook/OLE object stays clean)
- Status: Fixed
- Commit: `git log --grep "DT-011"`

### DT-012 — DDE detection gaps and fail-open `catch {}`
- Severity: High
- CWE: CWE-184, CWE-636
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:184-193 (`InspectWord`), :219-250 (`PartContainsDDE`)
- Description: (1) `Contains("DDE")` is case-sensitive, but Word accepts `ddeauto`. (2) `w:fldSimple/@w:instr` is ignored. (3) Each `w:instrText` is checked alone, so `DD` + `EAUTO` split across runs passes. (4) Only main/header/footer parts are scanned; footnotes, endnotes, comments and glossary are not. (5) `catch { }` returns false on any parse error (fail-open). (6) Excel DDE (`externalLinks/*.xml` `<ddeLink>`, `=cmd|'/c …'!A0` formulas) is not checked.
- Attack scenario / PoC: `<w:fldSimple w:instr=" DDEAUTO c:\\windows\\system32\\cmd.exe &quot;/k calc&quot; "/>` → *"Word document is clean."*.
- Fix: New `OfficeXmlContentScanner` runs in the first pass over **every** XML part (decided by content type, extension or leading bytes, so a renamed part cannot hide markup). It rebuilds complex-field instructions across runs (`fldChar` begin/separate/end with nesting, `instrText`/`delInstrText`), reads `fldSimple/@instr`, and compares the field type case-insensitively against `DDE`/`DDEAUTO`. A field whose type is produced by a nested field (`QUOTE` character-code obfuscation) is flagged. Excel `ddeLink`/`oleLink` elements and formulas or defined names containing a DDE reference (`|` outside string literals and quoted sheet names) are flagged. Malformed XML or any DTD raises `XmlException` → not clean. The SDK-based `PartContainsDDE` and its `catch {}` were removed.
- Regression test: OfficeDdeDetectionTests (16 cases: complex field, `fldSimple`, lowercase, split runs, nested QUOTE type, footnotes/endnotes/comments/glossary, Excel `ddeLink`, Excel DDE formula, malformed part, DOCTYPE in body, ordinary fields/formulas stay clean)
- Status: Fixed
- Commit: `git log --grep "DT-012"`

### DT-013 — Relationship analysis gaps and exponential traversal
- Severity: High
- CWE: CWE-184, CWE-407
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:252-270 (`HasSuspiciousRelationships`)
- Description: (1) No visited set: shared parts are revisited once per incoming path, so a chain of parts each referenced twice costs 2^depth visits (CPU DoS). (2) Only `ExternalRelationships` are inspected, but the SDK puts hyperlinks in `HyperlinkRelationships`. (3) Protocol-handler targets (`ms-msdt:` Follina-style, `search-ms:`, `ms-word:`, …) and `//host/share` UNC targets are not flagged (`\\host\share` happens to parse as `file://` and is caught). (4) Remote `frame` and `subDocument` relationships (auto-loaded on open) are not flagged. (5) PowerPoint `ppaction://program` / `ppaction://macro` actions are not checked. (6) `Contains("..")` flags benign URLs and misses encoded traversal. (7) Depth overflow throws `SecurityException`, whose message is echoed (DT-016).
- Attack scenario / PoC: an external hyperlink relationship to `ms-msdt:/id PCWDiagnostic …`, or a slide with `<a:hlinkHover action="ppaction://program" r:id="rIdX"/>` → clean.
- Fix: Relationship analysis moved into the single first pass, which parses each `.rels` part exactly once (no SDK recursion, no revisiting, so the exponential traversal is gone; the `SecurityException` depth guard is removed). Every relationship (not only `ExternalRelationships`) is checked: external `attachedTemplate`/`frame`/`subDocument` (remote templates/frames, CVE-2021-40444 class), external `oleObject`, UNC targets (`\\host\share`, `//host/share`), and any external scheme outside {http, https, mailto} — covering `ms-msdt:` (Follina), `search-ms:`, `ms-word:`, `file:`, `mhtml:`, `its:`, etc. PowerPoint `ppaction://program` and `ppaction://macro` actions are detected by the XML content scanner on `hlinkClick`/`hlinkHover`/`hlinkMouseOver`/`cNvPr`.
- Regression test: OfficeRelationshipTests (12 cases: remote template/frame/subdocument, UNC hyperlink, 6 protocol-handler schemes, external OLE, ppaction run-program, heavily cross-referenced parts complete quickly, ordinary http/mailto/internal rels stay clean)
- Status: Fixed
- Commit: `git log --grep "DT-013"`

### DT-014 — Every OOXML package is inspected as Word (Excel/PowerPoint branches dead)
- Severity: Low
- CWE: CWE-670
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:138-169 (`ScanModernOffice`)
- Description: `WordprocessingDocument.Open` succeeds on spreadsheet and presentation packages, so `InspectExcel`/`InspectPowerPoint` never run and type-specific checks would be skipped. Verified: an `.xlsx` is reported as *"Word document is clean."*. Also only `InvalidDataException` falls through to the next type, so any other open failure aborts the chain.
- Attack scenario / PoC: any workbook/presentation; impact today is wrong classification plus Word-only checks running on a workbook.
- Fix: The first pass parses `[Content_Types].xml` and `_rels/.rels` with a DTD-prohibiting reader (`SafeXml`), resolves the main part (root `officeDocument` relationship, transitional or strict) and its content type (Override, then Default), and derives the document kind. The scanner then opens only that SDK type; any failure is fail-closed. Packages without content types or root relationships, or with an unrecognised main content type, are rejected. Text extraction uses the same kind.
- Regression test: OfficeModernScanTests.ModernScan_Workbook_IsInspectedAsExcel; OfficeModernScanTests.ModernScan_Presentation_IsInspectedAsPowerPoint; OfficeModernScanTests.ModernScan_UnrecognisedMainContentType_FailsClosed; OfficeModernScanTests.ModernScan_PlainZipWithoutContentTypes_FailsClosed; OfficeModernScanTests.TextExtraction_Workbook_ReturnsCellText; OfficeModernScanTests.TextExtraction_Presentation_ReturnsSlideText
- Status: Fixed
- Commit: `git log --grep "DT-014"`

### DT-015 — Encrypted Office documents (legacy and CFB-wrapped OOXML) reported clean
- Severity: High
- CWE: CWE-636
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:80-83, :272-327 (`ScanLegacyOfficeAsync`)
- Description: Password-protected `.docx/.xlsx/.pptx` are CFB containers (`EncryptionInfo` + `EncryptedPackage`), so they take the legacy keyword path. Their content is ciphertext, no keyword matches, and the result is `IsClean = true`, `IsEncrypted = false`. RC4/CryptoAPI-encrypted `.doc` (`fEncrypted` FIB flag), `.xls` (`FILEPASS` record) and `.ppt` (`EncryptedSummary`) behave the same.
- Attack scenario / PoC: password-protect a macro-enabled `.docm` and upload it; the victim is given the password in the lure → *"Legacy heuristics passed."*.
- Fix: New bounded `CompoundFileInspector` (BCL only) parses the CFB header, FAT/DIFAT, directory and mini stream and reports `Encrypted` for: encrypted OOXML (`EncryptionInfo`/`EncryptedPackage` streams), Word `FibBase.fEncrypted`, an Excel `FILEPASS` record after `BOF`, and a PowerPoint `CurrentUserAtom.headerToken` of `0xE391C05F`. Every sector/directory chain uses a visited set and a hard iteration cap; any structural oddity yields `Unreadable` and the raw heuristic scan still runs. Encrypted files return `IsClean = false`, `IsEncrypted = true`, `IsScanned = false`. For non-seekable streams, and for OLE objects embedded in OOXML, the `EncryptedPackage`/`EncryptionInfo` stream names are matched by the keyword scanner (UTF-16LE). The loop guards were reviewed but deliberately not exercised with crafted cyclic files (see Residual risks).
- Regression test: OfficeEncryptionTests (10 cases: password-protected OOXML on seekable and non-seekable streams; encrypted .doc/.xls/.ppt; unencrypted .doc/.xls/.ppt stay clean; embedded encrypted package inside a .docx). Fixtures are written by the test helper `CfbBuilder` (valid acyclic CFB v3).
- Status: Fixed
- Commit: `git log --grep "DT-015"`

### DT-016 — Office results echo `ex.Message` and ZIP entry names (disclosure, log injection)
- Severity: Medium
- CWE: CWE-209, CWE-117
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:114, :123, :177, :406
- Description: `Message` embeds `entry.FullName` (attacker-controlled: may contain CR/LF, control characters, or misleading text) and raw `ex.Message` from System.IO.Packaging / the OpenXML SDK (internal part URIs, parser details). Applications commonly log or return `Message`.
- Attack scenario / PoC: an entry named `word/embeddings/a.exe\r\n[INFO] scan ok` forges log lines; exception text discloses internals to API clients.
- Fix: All Office result messages are now constant text: ZIP entry names are never echoed (oversized part, dangerous extension) and exception messages are no longer interpolated (structural failure, text extraction failure). The only remaining interpolations embed DocuTrust's own constant keyword/threat strings. Exceptions are still available to the caller as `InnerException` of `DocuTrustValidationException` for server-side logging.
- Regression test: OfficeMessageSafetyTests.ModernScan_DangerousEntryNameWithLineBreaks_IsNotEchoed; OfficeMessageSafetyTests.ModernScan_OversizedEntryName_IsNotEchoed (both fail on the old code); OfficeMessageSafetyTests.ModernScan_StructuralFailure_DoesNotEchoExceptionText (guard: the packaging exception for this input happened not to contain the name, so it also passed before)
- Status: Fixed
- Commit: `git log --grep "DT-016"`

### DT-017 — Office `GetPageAsync` reports `IsClean = true` without scanning; swallows parse errors
- Severity: Medium
- CWE: CWE-636
- Location: src/DocuTrust/Core/Services/DocuTrustOfficeScanner.cs:29-62, :329-409, :411-444
- Description: Text extraction returns `IsClean = true` for any input. Macro-laden documents, non-Office binaries routed to the "legacy" path, and packages that no SDK type can open (`catch { }` everywhere, empty text) are all reported clean. Combined with DT-009 (no size checks), extraction is also the easiest DoS path.
- Attack scenario / PoC: `GetPageAsync` on a `.docm` with VBA → `IsClean = true`; on an `.exe` → `IsClean = true` with "strings".
- Fix: `GetPageAsync` now runs the complete scan (`ScanCoreAsync`, shared with `ScanFileContentAsync`) first and returns the scan verdict without text when the document is not clean, so `IsClean = true` from extraction always means scanned and clean. Inputs that are neither OLE/CFB nor OOXML are rejected instead of having bytes extracted as strings. OOXML text is streamed from the body parts with `SafeXml` (no DOM, no `InnerText`), in document order (`sheet`/`sldId` relationship ids), skipping non-worksheet sheets such as chartsheets instead of throwing. All `catch { }` blocks are gone: any parse error is fail-closed. Extraction is capped at `FileSize.MaxExtractedTextChars` (10 M chars) for OOXML and legacy files; exceeding it is fail-closed.
- Regression test: OfficeTextExtractionTests (7 cases: macro-enabled document and legacy macro indicator are not clean and return no text, non-Office binary fails closed, clean document returns text, OOXML and legacy text caps fail closed, workbook with a chartsheet still extracts worksheet text)
- Status: Fixed
- Commit: `git log --grep "DT-017"`

### DT-018 — Scanners reuse one stream with `Position` resets (non-seekable streams crash)
- Severity: Low
- CWE: CWE-754
- Location: DocuTrustOfficeScanner.cs:43, :78, :128, :146-162, :346-395; DocuTrustPdfScanner.cs:151
- Description: Each scanner opens one stream and rewinds it with `stream.Position = 0` between passes. With a non-seekable `OpenReadStream()` this throws `NotSupportedException`, and a failed parser can leave the stream in an undefined state for the next attempt.
- Attack scenario / PoC: custom streaming `IFormFile` → exception instead of a verdict.
- Fix: Every pass opens a fresh stream with `IFormFile.OpenReadStream()` (the header read, the legacy scan, the ZIP pass, each OpenXML SDK attempt, each text-extraction attempt, and the PDF header/parse passes). No `Position` resets remain. The ZIP pass needs random access and now fails closed (`IsClean = false`, `IsScanned = false`) on a non-seekable stream instead of throwing. Streams opened by the scanners are disposed by the scanners; the caller-owned `IFormFile` is never disposed.
- Regression test: OfficeModernScanTests.LegacyScan_NonSeekableStream_ReturnsVerdict; OfficeModernScanTests.ModernScan_NonSeekableStream_FailsClosedWithoutThrowing; OfficeModernScanTests.LegacyTextExtraction_NonSeekableStream_ReturnsText; DocuTrustPdfScannerTests.ScanFileContentAsync_NonSeekableStream_ReturnsVerdict
- Status: Fixed
- Commit: `git log --grep "DT-018"`

### DT-019 — Undecryptable encrypted PDFs reported `IsClean = true`
- Severity: High
- CWE: CWE-636
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:162-165 (`CheckEncryptionAsync`), :24-25, :80-81
- Description: `PdfDocumentEncryptedException` produces `IsClean = true, IsEncrypted = true` and no content is scanned. `GetPageAsync` returns that result directly. Verified with a PDF carrying `/OpenAction` JavaScript and a `/Standard` handler with an unknown user password.
- Attack scenario / PoC: encrypt a malicious PDF with a user password, send the password in the phishing lure → `IsClean = true`.
- Fix: `PdfDocumentEncryptedException` now yields `IsClean = false`, `IsEncrypted = true`, `IsScanned = false` (consistent with encrypted Office files). PDFs that PdfPig can decrypt with an empty user password (owner-password-only, permissions-restricted) are still opened and scanned normally; see Breaking changes / Recommendations for rejecting those by policy.
- Regression test: PdfEncryptionTests.ScanFileContentAsync_UndecryptablePdf_IsNotClean; PdfEncryptionTests.GetPageAsync_UndecryptablePdf_IsNotClean
- Status: Fixed
- Commit: `git log --grep "DT-019"`

### DT-020 — PDF action chain: depth limit fails open; `/Next` arrays ignored
- Severity: High
- CWE: CWE-636
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:213, :238-241 (`IsActionMalicious`)
- Description: Past `MaxNestingDepth` (15) the method returns `false` ("not malicious"). `/Next` may be a single action or an **array** of actions (ISO 32000-1 §12.6.2); an array resolves to `null` and is ignored. There is no visited set (cycles rely on the fail-open depth limit).
- Attack scenario / PoC: `/OpenAction << /S /GoTo /D [...] /Next [ 5 0 R ] >>` with object 5 a JavaScript action, or a chain of 16 `GoTo` actions ending in JavaScript → clean.
- Fix: `IsActionMalicious` is now iterative with an explicit stack and a visited set of indirect references. `/Next` is followed whether it is a single action or an array of actions. Exceeding `FileSize.MaxNestingDepth` or revisiting an object (a cycle) now returns malicious (fail closed) instead of `false`.
- Regression test: PdfActionChainTests.Scan_JavaScriptInNextArray_IsDetected; PdfActionChainTests.Scan_JavaScriptBeyondDepthLimit_FailsClosed; PdfActionChainTests.Scan_CyclicActionChain_FailsClosedAndTerminates; PdfActionChainTests.Scan_ShortBenignActionChain_IsClean (no false positive)
- Status: Fixed
- Commit: `git log --grep "DT-020"`

### DT-021 — PDF objects that are streams with declared `/Length` > 25 MB are skipped
- Severity: Medium
- CWE: CWE-636
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:318-324 (`ResolveToDictionary`)
- Description: When an indirect object is a stream whose dictionary declares `/Length` above 25 MB, `null` is returned and callers treat the object as benign. The check uses the attacker-declared length (PdfPig's lenient parser recovers the real end of stream), and the bytes are already loaded by `GetObject`, so the skip saves nothing.
- Attack scenario / PoC: `3 0 obj << /S /JavaScript /JS (…) /Length 99999999 >> stream … endstream` as the `/OpenAction` target → clean.
- Fix: `ResolveToDictionary` returns the stream dictionary whatever the declared `/Length` is. The skip saved nothing (PdfPig has already parsed the object when `GetObject` returns) and only made the object invisible to the checks.
- Regression test: PdfOversizedObjectTests.Scan_ActionStoredAsStreamWithHugeDeclaredLength_IsDetected
- Status: Fixed
- Commit: `git log --grep "DT-021"`

### DT-022 — Missing PDF action types, annotation subtypes, form-field `/AA`, URI schemes
- Severity: High
- CWE: CWE-184
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:218-236 (`IsActionMalicious`), :280-291 (`IsAnnotationListMalicious`), :297-306 (`IsAcroFormSuspicious`)
- Description: Not detected: `/URI` actions with `javascript:`, `file:`, UNC or other non-web schemes; `/SubmitForm`, `/GoToE`, `/Rendition`, `/RichMediaExecute`, `/Sound`, `/Movie`; a `/JS` key without `/S`; annotation subtypes `/RichMedia`, `/Screen`, `/Movie`, `/Sound`, `/3D`; AcroForm field `/AA` and `/A` (keystroke/format/calculate scripts on fields without widgets). Comparisons are case-sensitive.
- Attack scenario / PoC: `/AcroForm << /Fields [6 0 R] >>` with field 6 carrying `/AA << /C << /S /JavaScript /JS (…) >> >>` → clean; link annotation with `/A << /S /URI /URI (javascript:…) >>` → clean.
- Fix: New `PdfThreatRules.Inspect(DictionaryToken)` with case-insensitive name comparison and constant messages, applied to every action in the `/OpenAction` chain, every annotation (plus its `/A` chain) and every AcroForm field. Rules: keys `/JS` (also without `/S`), `/JavaScript`, `/AA`, `/XFA`, `/EmbeddedFiles`, `/EF`, `/RichMediaContent`, `/RichMediaSettings`; `/S` in {JavaScript, JS, Launch, GoToR, ImportData, GoToE, SubmitForm, Rendition, RichMediaExecute, Sound, Movie}; `/S /URI` whose target is not http/https/mailto/relative (`javascript:`, `file:`, `smb:`, drive letters, UNC `\\` or `//`; whitespace/control characters stripped first); `/Subtype` in {FileAttachment, RichMedia, Screen, Movie, Sound, 3D}; `/Type /EmbeddedFile`. AcroForm `/Fields` and their `/Kids` are walked iteratively with a visited set and limits (depth, 100 000 fields), so field `/AA` scripts are found without a widget.
- Regression test: PdfActionCoverageTests (23 cases: 6 dangerous URI targets, 8 action types incl. case variants, /JS without /S, 5 annotation subtypes, field /AA without widget, kid field /A, ordinary links/mailto/fields stay clean)
- Status: Fixed
- Commit: `git log --grep "DT-022"`

### DT-023 — PDF objects off the hard-coded paths are never inspected; no raw-byte defense in depth
- Severity: Medium
- CWE: CWE-693
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:74-132 (`ScanFileContentAsync`)
- Description: Only the catalog `/OpenAction`, `/Names`, `/AA`, `/AcroForm` and page `/AA`/`/Annots` are checked. Actions reachable through outlines (bookmarks), named destinations, structure trees, nested annotation dictionaries (e.g. `/Parent`, `/Popup`) and objects that a different reader may resolve differently (unreferenced objects, earlier incremental-update revisions) are never examined. No raw-byte scan exists to catch what the parser did not surface.
- Attack scenario / PoC: an outline item `/A << /S /Launch /F (cmd.exe) >>` → clean; JavaScript in an older incremental-update revision.
- Fix: (1) New `PdfStructureWalker` visits every object reachable from the catalog (pages, annotations and their `/Popup`/`/Parent`, outlines, name trees, fields, optional content, objects in compressed object streams) and applies `PdfThreatRules` to each dictionary. It is iterative with a visited set, limits of 200 000 objects and 64 levels of inline nesting (exceeding either fails closed), skips subtrees that cannot carry actions (`/Contents`, `/Resources`, fonts, `/Metadata`, `/Thumb`, `/StructTreeRoot`), and treats a reference to an undefined object as null per ISO 32000-1 §7.3.10; any other parse error fails closed. It replaces the `GetPages()` loop, which also parsed every page content stream. (2) New `PdfRawScanner` runs before PdfPig: a byte-level tokenizer over the whole file (bounded by `MaxPdfSizeBytes` actual bytes) that decodes `#xx` escapes, compares names case-insensitively and skips stream bodies (KMP match for `endstream`). It flags `/JavaScript /JS /Launch /EmbeddedFile(s) /EF /FileAttachment /RichMedia* /XFA /AA /ImportData /GoToE /GoToR /SubmitForm /Rendition /Sound /Movie /Screen /3D`, so unreferenced objects and earlier incremental-update revisions are covered, and hostile files never reach the parser. `/OpenAction` is deliberately **not** a raw keyword: it is the normal "open at page/zoom" mechanism in benign PDFs (e.g. every hyperref/LaTeX file), and its target is validated structurally.
- Regression test: PdfDeepInspectionTests.Scan_OutlineLaunchActionInObjectStream_IsDetectedStructurally; PdfDeepInspectionTests.Scan_AnnotationPopupWithJavaScriptInObjectStream_IsDetectedStructurally; PdfDeepInspectionTests.Scan_UnreferencedObjectWithEscapedJavaScript_IsDetectedByRawScan; PdfDeepInspectionTests.Scan_DanglingReferenceAndNamesInsideStreams_AreClean and Scan_CleanObjectStreamDocument_IsClean (no false positives)
- Status: Fixed
- Commit: `git log --grep "DT-023"`

### DT-024 — `#xx`-escaped PDF names bypass structural checks
- Severity: Info
- CWE: CWE-180
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs (all `NameToken` comparisons)
- Description: Lead: `/J#61vaScript` would not equal `JavaScript`. Probe result: PdfPig decodes `#xx` escapes while tokenising (`NameToken.Data == "JavaScript"`), and the existing scanner already flags such a file. The raw-byte scan added for DT-023 must decode escapes itself.
- Attack scenario / PoC: `/S /J#61vaScript` → detected at baseline.
- Fix: No code change for the structural path: PdfPig decodes `#xx` escapes while tokenising, so `/S /J#61vaScript` is seen as `JavaScript` (probe and regression test, which also passes on the pre-audit code). The new raw-byte scan (DT-023) decodes escapes itself, so escaped names are caught there too.
- Regression test: PdfDeepInspectionTests.Scan_EscapedJavaScriptNameInObjectStream_IsDetectedStructurally (structural path); PdfDeepInspectionTests.Scan_UnreferencedObjectWithEscapedJavaScript_IsDetectedByRawScan (raw path)
- Status: Not an issue
- Commit: test added with DT-023 (`git log --grep "DT-023"`)

### DT-025 — PDF `GetPageAsync` reports `IsClean = true` without a threat scan; file parsed 2–3 times
- Severity: Medium
- CWE: CWE-636, CWE-400
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:18-72 (`GetPageAsync`), :79-84, :153
- Description: `GetPageAsync` checks only encryption and then returns `IsClean = true` together with the text, even for PDFs with JavaScript or `/Launch`. Both public methods parse the file twice (`CheckEncryptionAsync` + main parse), and the existing `GetPages()` loop in the scan parses every page's content stream just to read annotations.
- Attack scenario / PoC: `GetPageAsync(1, 1, maliciousPdf)` → `IsClean = true`.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-026 — No PDF page-count, glyph or extracted-text limits
- Severity: Medium
- CWE: CWE-770
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:30-46, :53-61 (`GetPageAsync`)
- Description: All pages are extracted into one `StringBuilder` without a page cap, a per-page glyph cap (nearest-neighbour word extraction is super-linear) or a total-character cap.
- Attack scenario / PoC: a 150 MB PDF with tens of thousands of pages, or one page with millions of glyphs → CPU/memory exhaustion.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-027 — PDF/ZIP polyglots not detected
- Severity: Low
- CWE: CWE-693
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs (no check)
- Description: A valid PDF with a ZIP archive appended (or embedded between objects) passes as a clean PDF. The same bytes open as a ZIP/JAR/OOXML package in other consumers (ZIP readers locate the end-of-central-directory record from the end of the file).
- Attack scenario / PoC: `cat clean.pdf payload.zip > upload.pdf` → clean PDF; a downstream service or user opens it as an archive.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-028 — PdfPig 0.1.14 has known infinite-recursion (stack overflow) bugs
- Severity: High
- CWE: CWE-674, CWE-1395
- Location: src/DocuTrust/DocuTrust.csproj:33 (`PdfPig 0.1.14`)
- Description: PdfPig 0.1.15 and 0.1.16 fix unbounded recursion in composite-glyph parsing (#1237, #1347), colour-space resolution (#1354) and CMap parsing (#1394), and add a stack-depth guard for nested objects. In .NET a `StackOverflowException` cannot be caught: one hostile PDF terminates the whole ASP.NET Core process.
- Attack scenario / PoC: upload a PDF with a self-referencing composite glyph or colour space → host process crash (repeatable DoS).
- Fix: Upgraded `PdfPig` 0.1.14 → 0.1.16 in the library and the test project. 0.1.16 adds nullable annotations, so three `TryGet` call sites were adapted (no behaviour change). Not reproduced in-house (crafting a host-crashing PDF is out of scope); the guard is a version check on the resolved runtime assembly. Remaining stack-overflow risk in third-party parsers is documented under Residual risks.
- Regression test: DependencyVersionTests.PdfPig_ResolvedVersion_IncludesRecursionFixes
- Status: Fixed
- Commit: `git log --grep "DT-028"`

### DT-029 — Empty `expectedExtension` makes `ValidateFileAsync` accept any type, including executables
- Severity: High
- CWE: CWE-434
- Location: src/DocuTrust/Core/Services/DocuTrustFileScanner.cs:224-246 (`ValidateFileAsync`)
- Description: With `expectedExtension` null/empty, any recognised format (PE executable, ELF, MSI, JAR, …) returns `IsValid = true`. The other two validation methods throw for the same input, so the behaviour is inconsistent and fails open.
- Attack scenario / PoC: an application that passes an optional/empty "expected type" from configuration accepts `malware.exe` as valid.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-030 — Client filename extension ignored (double extensions, docs claim otherwise)
- Severity: Medium
- CWE: CWE-434
- Location: src/DocuTrust/Core/Services/DocuTrustFileScanner.cs:203-292 (`ValidateFileAsync`); docs/getting-started.md ("This checks both the extension AND the magic bytes")
- Description: Only magic bytes are compared with `expectedExtension`; `IFormFile.FileName` is never checked. Applications that store files under the client-supplied name end up with `report.pdf.html` / `x.pdf.exe` / `x.html` files whose bytes are a valid PDF, which leads to stored XSS or execution depending on the serving stack.
- Attack scenario / PoC: upload `<valid PDF bytes>` named `invoice.html` with `expectedExtension = ".pdf"` → `IsValid = true`.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-031 — Validator has no size limit before container (ZIP/OLE) parsing
- Severity: Medium
- CWE: CWE-400
- Location: src/DocuTrust/Core/Services/DocuTrustFileScanner.cs:42, :102, :165, :222
- Description: `FileFormatInspector` opens ZIP-based (OOXML) candidates with `ZipArchive` and OLE candidates with `OpenMcdf` to tell formats apart. None of the validation methods applies `FileSize.MaxFileSizeBytes`, so arbitrarily large containers (huge central directories, see DT-009) are parsed by a plain "check the type" call.
- Attack scenario / PoC: multi-GB ZIP with millions of central-directory entries passed to `ValidateFileStreamAsync`.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-032 — Validator leaves the caller's stream at a changed position
- Severity: Low
- CWE: CWE-664
- Location: src/DocuTrust/Core/Services/DocuTrustFileScanner.cs:102 (`ValidateFileStreamAsync`)
- Description: Verified: the inspector seeks to 0, reads, and leaves the stream at 0 regardless of where the caller had positioned it. Callers that then save/forward the stream from their own position get wrong data.
- Attack scenario / PoC: functional integrity issue; a caller at offset N saves a different byte range than it validated.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-033 — Validator exceptions embed the client filename and full path
- Severity: Low
- CWE: CWE-209, CWE-117
- Location: src/DocuTrust/Core/Services/DocuTrustFileScanner.cs:82, :197, :288
- Description: `DocuTrustValidationException` messages contain `file.FileName` (attacker-controlled, may contain CR/LF) and full server paths. Exception messages are often logged verbatim or returned by default error handlers.
- Attack scenario / PoC: upload a malformed OLE file named `x\r\n2026-10-13 INFO user=admin login ok.doc` → forged log line; path disclosure via error pages.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-034 — Path APIs block forever on FIFOs/devices; no regular-file checks
- Severity: Medium
- CWE: CWE-400, CWE-22, CWE-59
- Location: src/DocuTrust/Core/Services/DocuTrustFileScanner.cs:41 (`ValidateFilePathAsync`), :163 (`GetFileTypeAsync`)
- Description: `new FileStream(path, …)` on a FIFO blocks in `open(2)` until a writer appears (thread-pool starvation); character devices (`/dev/tty`) block on read. Directories produce exceptions that include the path. Path traversal, symlinks and UNC paths (Windows: NTLM authentication to a remote host) are the caller's responsibility but are not documented.
- Attack scenario / PoC: application validates a user-influenced path such as an upload staging name; a FIFO in that location hangs the request thread forever.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-035 — Vulnerable `OpenMcdf 3.1.0` (uncatchable infinite loops) reachable from uploads
- Severity: High
- CWE: CWE-835, CWE-1395
- Location: src/DocuTrust/DocuTrust.csproj:32 (`FileSignatures 7.0.0` → `OpenMcdf 3.1.0`)
- Description: CVE-2026-41511 / GHSA-jxpf-xq2m-q525 (fixed 3.1.3) and CVE-2026-45785 / GHSA-5qwm-7pvp-w988 (fixed 3.1.4): a CFB directory whose sibling links form a cycle makes enumeration/lookup loop forever without throwing. Verified that `ValidateFileAsync` drives `OpenMcdf` for any file with the OLE magic, so a few hundred bytes hang a request thread permanently.
- Attack scenario / PoC: upload a crafted `.doc` with a directory cycle repeatedly → thread-pool exhaustion.
- Fix: Upgraded `FileSignatures` 7.0.0 → 7.3.0 (no API changes; 7.1 bumped OpenMcdf to 3.1.3 and 7.2.1 to 3.1.4). `dotnet list package --vulnerable --include-transitive` is now clean for the library. Not reproduced in-house: the guard is a version check on the resolved runtime assembly.
- Regression test: DependencyVersionTests.OpenMcdf_ResolvedVersion_IncludesDirectoryCycleFixes; DependencyVersionTests.FileSignatures_ResolvedVersion_DependsOnPatchedOpenMcdf
- Status: Fixed
- Commit: `git log --grep "DT-035"`

### DT-036 — Vulnerable test-only transitive packages
- Severity: Low
- CWE: CWE-1395
- Location: tests/DocuTrust.UnitTests/DocuTrust.UnitTests.csproj:16 (`xunit 2.6.2` → `NETStandard.Library 1.6.1`)
- Description: `System.Net.Http 4.3.0` (GHSA-7jgj-8wvc-jh57) and `System.Text.RegularExpressions 4.3.0` (GHSA-cmhx-cq75-c4mj) are restored for the test project. Not shipped in the package, but they run on developer machines and CI and keep `--vulnerable` noisy.
- Attack scenario / PoC: n/a (test tooling).
- Fix: Upgraded `xunit` 2.6.2 → 2.9.3 and `xunit.runner.visualstudio` 2.5.4 → 2.8.2. xunit 2.9.x ships a netstandard2.0 asset without the `NETStandard.Library 1.6.1` dependency, so the vulnerable 4.3.0 packages are no longer restored and no new packages were added. `Microsoft.NET.Test.Sdk` was left at 17.8.0 (not vulnerable).
- Regression test: n/a at runtime (test tooling); enforced by the `dotnet list package --vulnerable` CI gate added for DT-038
- Status: Fixed
- Commit: `git log --grep "DT-036"`

### DT-037 — `FileSize` constants use `int` arithmetic
- Severity: Info
- CWE: CWE-190
- Location: src/DocuTrust/Core/Constants/FileSize.cs:5-9
- Description: `100 * 1024 * 1024` is evaluated as `int` before widening. Verified reasoning: these are constant expressions, so raising one past 2,047 MB is a **compile-time** error (CS0220), not a silent runtime overflow. Maintenance hazard only.
- Attack scenario / PoC: none.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-038 — CI never runs tests (and cannot read `.slnx` with SDK 8)
- Severity: Low
- CWE: CWE-1053 (process)
- Location: .github/workflows/build.yml:1-12
- Description: The workflow only restores and builds. `dotnet restore` at the root picks up `DocuTrust.slnx`, which the pinned SDK 8.0.x cannot read, so the build itself likely fails. No `dotnet test`, no vulnerable-package gate, no `permissions:` block (default token scope), and `actions/checkout@v3`/`setup-dotnet@v3` are deprecated (Node 16).
- Attack scenario / PoC: security regressions merge unnoticed.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-039 — No scan time limits
- Severity: Medium
- CWE: CWE-400
- Location: DocuTrustOfficeScanner.cs, DocuTrustPdfScanner.cs (public entry points)
- Description: Scans run until completion unless the caller passes a cancellable token. Pathological but in-limit inputs (deep relationship graphs, huge glyph counts, complex XML) can hold a request thread for minutes.
- Attack scenario / PoC: a handful of slow-to-parse uploads exhausts the thread pool.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-040 — Content scanners are internal; public API only checks magic bytes
- Severity: Info
- CWE: CWE-1059 (documentation)
- Location: src/DocuTrust/Core/Services/DocuTrustPdfScanner.cs:15, DocuTrustOfficeScanner.cs:18, Extensions/DocuTrustExtensions.cs:20-21, README.md "Features"
- Description: `DocuTrustPdfScanner` and `DocuTrustOfficeScanner` are `internal`, so consumers cannot call them (the samples would not compile outside the assembly). `AddDocuTrust` registers them, but they cannot be resolved by type. The README advertises macro/DDE/JavaScript scanning, so consumers who call `IDocuTrustFileValidator` believe they get content scanning but only get magic-byte checks.
- Attack scenario / PoC: a consumer relies on `ValidateFileAsync(file, ".docx")` to block macro documents → macros are accepted.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-041 — XML parsing: DTD/XXE settings
- Severity: Info
- CWE: CWE-611, CWE-776
- Location: DocuTrustOfficeScanner.cs:227-233 (`PartContainsDDE`); OpenXML SDK / System.IO.Packaging internal readers
- Description: Audited every XML load path. `PartContainsDDE` uses `DtdProcessing.Prohibit` + `XmlResolver = null`; System.IO.Packaging and the OpenXML SDK 3.x create readers with `DtdProcessing.Prohibit` (default on .NET Core) and no resolver. No `XmlDocument`/`XDocument` loads with DTDs exist. Expected verdict: not an issue; new XML readers added by this audit must keep the same settings.
- Attack scenario / PoC: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` in a part.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

### DT-042 — Thread safety of shared instances (other than the pool)
- Severity: Info
- CWE: CWE-362
- Location: DocuTrustOfficeScanner.cs:21 (`MaliciousExts`), DocuTrustFileScanner.cs:14 (`_inspector`)
- Description: Reviewed all static/shared state. `MaliciousExts` is a static `HashSet` that is only read after type initialisation (safe for concurrent reads). `FileFormatInspector` holds a `readonly IEnumerable<FileFormat>` and no mutable state (verified by reflection), and `DocuTrustFileScanner` is registered scoped. The only shared mutable state is the custom pool (DT-003/DT-005).
- Attack scenario / PoC: none.
- Fix: TBD
- Regression test: TBD
- Status: Open
- Commit: —

---

## Breaking changes / Recommendations

_To be completed as fixes land._

## Residual risks

_To be completed as fixes land._
