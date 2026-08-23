using System.Collections.Concurrent;
using System.Diagnostics;

namespace ODOLDecrypt;

internal static class Program
{
    private static int Main(string[] args)
    {
        string? outDir = null;
        bool recursive = false, overwrite = false, inPlace = false, copyPlain = false;
        var inputs = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-o" or "--out" when i + 1 < args.Length:
                    outDir = args[++i];
                    break;
                case "-r" or "--recursive":
                    recursive = true;
                    break;
                case "--overwrite" or "-f":
                    overwrite = true;
                    break;
                case "--inplace":
                    inPlace = true;
                    break;
                case "-c" or "--copy-plain":
                    copyPlain = true;
                    break;
                case "-h" or "--help":
                    PrintUsage();
                    return 0;
                default:
                    inputs.Add(a);
                    break;
            }
        }

        if (inputs.Count == 0)
        {
            PrintUsage();
            return 2;
        }

        var files = ExpandInputs(inputs, recursive);
        if (files.Count == 0)
        {
            Console.Error.WriteLine("No .p3d files matched the given inputs.");
            return 2;
        }

        if (outDir != null) Directory.CreateDirectory(outDir);
        if (inPlace) overwrite = true;

        Console.WriteLine($"ODOLDecrypt - {files.Count} file(s)");
        var failures = new ConcurrentBag<string>();
        int decrypted = 0, skipped = 0, copied = 0;
        var clock = Stopwatch.StartNew();

        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            file =>
            {
                try
                {
                    switch (ProcessFile(file, outDir, overwrite, inPlace, copyPlain))
                    {
                        case ProcResult.Decrypted: Interlocked.Increment(ref decrypted); break;
                        case ProcResult.Copied: Interlocked.Increment(ref copied); break;
                        default: Interlocked.Increment(ref skipped); break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[FAIL] {file}: {ex.Message}");
                    failures.Add(file);
                }
            });

        clock.Stop();
        Console.WriteLine($"Done in {clock.Elapsed.TotalSeconds:0.00}s - " +
                          $"{decrypted} decrypted, {copied} copied, {skipped} skipped, {failures.Count} failed.");
        return failures.Count == 0 ? 0 : 1;
    }

    private enum ProcResult { Skipped, Decrypted, Copied }

    /// <returns>what happened to the file.</returns>
    private static ProcResult ProcessFile(string path, string? outDir, bool overwrite, bool inPlace, bool copyPlain)
    {
        byte[] data = File.ReadAllBytes(path);
        var info = OdolV75Decryptor.Analyse(data);

        if (!info.IsOdol)
        {
            Console.WriteLine($"[SKIP] {path}: not an ODOL model");
            return ProcResult.Skipped;
        }
        if (info.Version < 75)
        {
            Console.WriteLine($"[SKIP] {path}: ODOL v{info.Version} is not encrypted (v75+ only)");
            return ProcResult.Skipped;
        }
        if (!info.Encrypted)
        {
            // plaintext model (e.g. Global Mobilization ships unencrypted v75).
            // With --copy-plain it still lands in the output folder so batch
            // jobs over mixed directories produce a complete file set.
            if (copyPlain && outDir != null && !inPlace)
            {
                string copyTarget = Path.Combine(outDir, Path.GetFileName(path));
                if (!overwrite && File.Exists(copyTarget))
                    throw new IOException($"output exists: {copyTarget} (use --overwrite)");
                File.Copy(path, copyTarget, overwrite);
                uint copyAppId = BitConverter.ToUInt32(data, 16);
                Console.WriteLine($"[COPY] {path} -> {copyTarget}  (app_id={copyAppId}, already plain)");
                return ProcResult.Copied;
            }
            Console.WriteLine($"[SKIP] {path}: already decrypted (enc fields are zero)");
            return ProcResult.Skipped;
        }
        string? usedName = null;
        if (info.NameHashVariant)
        {
            // enc1 bit1: the tweak mixes an FNV-1a hash of the model-name suffix,
            // which is unknown to us. Try every plausible name candidate and keep
            // the one whose decryption yields a sane plaintext header.
            bool cracked = false;
            foreach (string cand in CandidateNames(path))
            {
                byte[] attempt = OdolV75Decryptor.Decrypt((byte[])data.Clone(), info.Enc1, info.Enc2, cand);
                if (!LooksLikePlainODOL(attempt)) continue;
                data = attempt;
                usedName = cand;
                cracked = true;
                break;
            }
            if (!cracked)
                throw new IOException("name-hash tweak variant: no candidate model name matched");
        }
        else
        {
            OdolV75Decryptor.Decrypt(data, info.Enc1, info.Enc2);
        }

        uint appId = BitConverter.ToUInt32(data, 16);
        string prefix = ReadAsciiZ(data, 20);

        string target;
        if (inPlace)
        {
            target = path;
        }
        else if (outDir != null)
        {
            target = Path.Combine(outDir, Path.GetFileName(path));
        }
        else
        {
            target = Path.Combine(
                Path.GetDirectoryName(path)!,
                Path.GetFileNameWithoutExtension(path) + "_decrypted.p3d");
        }

        if (!overwrite && !inPlace && File.Exists(target))
            throw new IOException($"output exists: {target} (use --overwrite)");

        File.WriteAllBytes(target, data);
        string extra = usedName != null ? $", name=\"{usedName}\"" : "";
        Console.WriteLine($"[OK]   {path} -> {target}  (app_id={appId}, prefix=\"{prefix}\"{extra})");
        return ProcResult.Decrypted;
    }

    /// <summary>Heuristic check that decryption produced a sane plaintext ODOL header.</summary>
    private static bool LooksLikePlainODOL(byte[] d)
    {
        if (d.Length < 32) return false;
        uint appId = BitConverter.ToUInt32(d, 16);
        if (appId == 0 || appId > 100_000_000) return false;   // plausible Steam AppID
        int printable = 0;
        for (int i = 20; i < d.Length && i < 280; i++)
        {
            if (d[i] == 0) return printable >= 4;              // end of p3d_prefix
            if (d[i] is < 32 or > 126) return false;           // prefix must be ASCII
            printable++;
        }
        return printable >= 4;
    }

    /// <summary>Model-name candidates tried for the FNV name-hash tweak variant.</summary>
    private static IEnumerable<string> CandidateNames(string path)
    {
        string full = Path.GetFullPath(path);
        var list = new List<string>
        {
            Path.GetFileName(full),                                        // name.p3d
            Path.GetFileNameWithoutExtension(full),                        // name
            full.Replace('/', '\\'),                                       // full path backslash
            full.Replace('\\', '/'),                                       // full path slash
        };
        return list.Distinct(StringComparer.Ordinal);
    }

    private static string ReadAsciiZ(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return System.Text.Encoding.ASCII.GetString(data, offset, Math.Min(end, offset + 260) - offset);
    }

    private static List<string> ExpandInputs(IEnumerable<string> inputs, bool recursive)
    {
        var set = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string input in inputs)
        {
            if (Directory.Exists(input))
            {
                var opts = recursive
                    ? SearchOption.AllDirectories
                    : SearchOption.TopDirectoryOnly;
                foreach (var f in Directory.EnumerateFiles(input, "*.p3d", opts))
                    set.Add(f);
            }
            else if (input.Contains('*') || input.Contains('?'))
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(input))!;
                string pattern = Path.GetFileName(input);
                foreach (var f in Directory.EnumerateFiles(dir, pattern))
                    set.Add(f);
            }
            else if (File.Exists(input))
            {
                set.Add(input);
            }
            else
            {
                Console.Error.WriteLine($"[WARN] input not found: {input}");
            }
        }
        return [.. set];
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            ODOLDecrypt — decryptor for encrypted Arma 3 ODOL v75 models (Creators DLC)

            Usage:
              ODOLDecrypt <inputs...> [-o <outdir>] [-r] [-c] [--overwrite] [--inplace]

              <inputs...>       .p3d files, wildcards (*.p3d) or directories
              -o, --out <dir>   write decrypted files into <dir>
              -r, --recursive   recurse into directories
              -f, --overwrite   overwrite existing outputs
                  --inplace     replace input files with their decrypted versions
              -c, --copy-plain  also copy already-plaintext models into <dir>

            Decrypted files keep the ODOL v75 format and can be read by regular
            Arma modding tools (arma-file-formats, BIS.P3D, Object Builder, ...).
            """);
    }
}
