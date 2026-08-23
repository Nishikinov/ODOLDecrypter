namespace ODOLDecrypt;

/// <summary>
/// Decrypts Arma 3 "Creators DLC" protected ODOL v75 models.
///
/// File layout (plaintext header):
///   +0  "ODOL", +4 version u32 (=75), +8 enc1 u32, +12 enc2 u32
///   Everything from offset 16 onward is encrypted while (enc1 != 0 || enc2 != 0);
///   the first 16 stream bytes are never part of the ciphertext.
///
/// Cipher: per-4096-byte-block RC4.
///   key16 = DeriveKey(enc1, enc2)
///   tweak = ComputeTweak(streamSize)                     // enc1 bit1 clear
///         = ComputeTweakNameHashed(size, modelName)      // enc1 bit1 set
///   block seed  = (blockPos ^ tweak)
///   working key = key16 XOR repeat_le32(~tweak ^ blockPos)
///   S-box starts as identity, standard RC4 KSA with the working key,
///   then LCG(seed)-driven number of PRGA pre-steps in [256..512],
///   then the PRGA index roles i/j are swapped and the block is XORed.
///
/// Key material lives inside arma3_x64.exe:
///   table A @ 0x141B731E8, table B @ 0x141B73200,
///   tolower table @ 0x141A959D0, "\/" alphabet @ 0x141B731E4.
/// </summary>
public static class OdolV75Decryptor
{
    private static readonly byte[] TableA =
    [
        0x28, 0x4C, 0x36, 0x4A, 0x7F, 0x23, 0xE6, 0x3B,
        0x48, 0x74, 0x6F, 0x78, 0xDF, 0x3A, 0xB8, 0x0C
    ];

    private static readonly byte[] TableB =
    [
        0x20, 0x89, 0x25, 0x8E, 0x88, 0xF7, 0x19, 0xCF,
        0x6E, 0xC2, 0xF8, 0x8D, 0x65, 0xB5, 0x48, 0x64
    ];

    public const int HeaderSize = 16;
    public const int BlockSize = 4096;
    private const uint MinSwaps = 256;
    private const uint MaxSwaps = 512;

    public sealed class Analysis
    {
        public bool IsOdol;
        public uint Version;
        public uint Enc1;
        public uint Enc2;
        public bool Encrypted => Version >= 75 && (Enc1 != 0 || Enc2 != 0);

        /// <summary>Bit 1 of enc1 selects the FNV(name)-mixed tweak variant.</summary>
        public bool NameHashVariant => (Enc1 & 2) != 0;
    }

    public static Analysis Analyse(ReadOnlySpan<byte> data)
    {
        var a = new Analysis();
        if (data.Length < HeaderSize || data[0] != 'O' || data[1] != 'D' || data[2] != 'O' || data[3] != 'L')
            return a;
        a.IsOdol = true;
        a.Version = BitConverter.ToUInt32(data.Slice(4, 4));
        if (a.Version >= 75)
        {
            a.Enc1 = BitConverter.ToUInt32(data.Slice(8, 4));
            a.Enc2 = BitConverter.ToUInt32(data.Slice(12, 4));
        }
        return a;
    }

    /// <summary>Derives the 16-byte RC4 key from the enc fields stored in the header.</summary>
    public static byte[] DeriveKey(uint enc1, uint enc2)
    {
        bool altTable = (enc1 & 4) != 0;
        byte[] table = altTable ? TableB : TableA;
        // Verified mode: bit2 clear -> constant seed 0x25 with table A.
        // The alternate branch uses bits 16+ of enc1 as its seed with table B
        // (reconstructed from disassembly, not exercised by known DLC files).
        int s = altTable ? (int)((enc1 >> 16) & 0xFF) : 0x25;

        var key = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            bool bump = s % 3 != 0;
            int val = bump ? s + 7 : s;
            key[i] = (byte)((val & 0x7F) ^ table[i]);
            s = bump ? val : s + 1;
        }
        _ = enc2; // observed always zero for mode A files
        return key;
    }

    /// <summary>Tweak derived from the stream size reported by the engine (enc1 bit1 clear).</summary>
    public static uint ComputeTweak(uint size)
    {
        uint b = size & 0xFF;
        int sr = (int)((b >> 3) & 7);
        int sl = (8 - (int)(b & 7)) & 7;
        return ((size >> sr) | (size << sl)) ^ size;
    }

    private static ulong Fnv1aLowered(ReadOnlySpan<byte> data)
    {
        const ulong basis = 0xCBF29CE484222325;
        const ulong prime = 0x100000001B3;
        ulong h = basis;
        foreach (byte ch in data)
            h = (h ^ ToLowerByte(ch)) * prime;
        return h;

        static byte ToLowerByte(byte ch) =>
            ch is >= (byte)'A' and <= (byte)'Z' ? (byte)(ch + 32) : ch;
    }

    /// <summary>
    /// Tweak for the name-hashed variant (enc1 bit1 set): the native code hashes
    /// the part of the model name after its last '/' or '\' delimiter (whole name
    /// when there is none) with FNV-1a over a lowered byte table, then mixes
    /// rotations of that hash and of the stream size.
    /// </summary>
    public static uint ComputeTweakNameHashed(uint size, string modelName)
    {
        Span<byte> nameBytes = stackalloc byte[512];
        int len = System.Text.Encoding.ASCII.GetBytes(modelName ?? string.Empty, nameBytes);

        // find start of the last path component
        int start = 0;
        for (int i = len - 1; i >= 0; i--)
        {
            if (nameBytes[i] == (byte)'\\' || nameBytes[i] == (byte)'/')
            {
                start = i + 1;
                break;
            }
        }

        ulong f = Fnv1aLowered(nameBytes[start..len]);

        uint fb = (uint)f & 0xFF;
        int fs = (int)((fb >> 3) & 7);
        int fl = (8 - (int)(fb & 7)) & 7;
        uint a = (uint)(((f >> fs) | (f << fl)) & 0xFFFFFFFF);

        uint b = size & 0xFF;
        int sr = (int)((b >> 3) & 7);
        int sl = (8 - (int)(b & 7)) & 7;
        uint bb = ((size >> sr) | (size << sl));

        return a ^ bb ^ size ^ (uint)f;
    }

    private static uint LcgSwaps(uint seed)
    {
        uint s = (seed * 0xC1C64E6Du + 0x3039u) & 0x7FFFFFFFu;
        float u = s * 4.656613e-10f;
        float v = u * 256f - 0.5f;
        // cvtss2si rounds half to even — MathF.Round does the same.
        int n = (int)MathF.Round(v) + 256;
        return (uint)Math.Clamp(n, (int)MinSwaps, (int)MaxSwaps);
    }

    /// <summary>Decrypts <paramref name="data"/> in place and returns it.</summary>
    public static byte[] Decrypt(byte[] data, uint enc1, uint enc2, string? modelName = null)
    {
        byte[] key = DeriveKey(enc1, enc2);
        uint tweak = (enc1 & 2) != 0
            ? ComputeTweakNameHashed((uint)data.Length, modelName ?? string.Empty)
            : ComputeTweak((uint)data.Length);
        Span<byte> w = stackalloc byte[16];

        for (long pos = 0; pos < data.Length; pos += BlockSize)
        {
            uint mm = (~tweak ^ (uint)pos);
            for (int i = 0; i < 16; i++)
                w[i] = (byte)(key[i] ^ (byte)(mm >> (8 * (i & 3))));

            // standard RC4 KSA over an identity S-box
            var S = new int[256];
            for (int i = 0; i < 256; i++) S[i] = i;
            int j = 0;
            for (int n = 0; n < 256; n++)
            {
                j = (j + S[n] + w[n % 16]) & 0xFF;
                (S[n], S[j]) = (S[j], S[n]);
            }

            int ii = 0, jj = 0;
            uint swaps = LcgSwaps((uint)(pos ^ tweak));
            for (uint k = 0; k < swaps; k++)
            {
                ii = (ii + 1) & 0xFF;
                jj = (jj + S[ii]) & 0xFF;
                (S[ii], S[jj]) = (S[jj], S[ii]);
            }
            // native code exchanges the PRGA index roles after the drop
            (ii, jj) = (jj, ii);

            long lo = pos == 0 ? HeaderSize : pos;
            long hi = Math.Min(pos + BlockSize, data.Length);
            for (long o = lo; o < hi; o++)
            {
                ii = (ii + 1) & 0xFF;
                jj = (jj + S[ii]) & 0xFF;
                (S[ii], S[jj]) = (S[jj], S[ii]);
                data[o] ^= (byte)S[(S[ii] + S[jj]) & 0xFF];
            }
        }

        // A properly decrypted model must advertise itself as plaintext,
        // otherwise engines/parsers would try to decrypt it a second time.
        Array.Clear(data, 8, 8);
        return data;
    }
}
