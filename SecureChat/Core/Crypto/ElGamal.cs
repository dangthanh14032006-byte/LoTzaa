using System.Numerics;

namespace SecureChat.Core.Crypto;

/// <summary>Cặp khóa ElGamal: x là khóa riêng, y = g^x mod p là khóa công khai.</summary>
public sealed class ElGamalKeyPair
{
    public required BigInteger PublicKeyY { get; init; }
    public required BigInteger PrivateKeyX { get; init; }

    public RsaKeyPair? Rsa { get; init; }
}

/// <summary>Một khối bản mã ElGamal: (c1, c2) = (g^k mod p, m * y^k mod p).</summary>
public readonly struct ElGamalBlock
{
    public BigInteger C1 { get; }
    public BigInteger C2 { get; }
    public ElGamalBlock(BigInteger c1, BigInteger c2) { C1 = c1; C2 = c2; }
}

/// <summary>
/// ElGamal trên nhóm MODP 2048-bit an toàn (RFC 3526, nhóm 14): p nguyên tố an toàn,
/// q = (p-1)/2 cũng nguyên tố, sinh g = 2. Dùng cho: (1) mã hóa bất đối xứng dữ liệu ngắn
/// (thường là khóa phiên AES được trao đổi giữa hai người dùng), và (2) chữ ký số ElGamal.
/// Với văn bản dài, hệ thống này KHÔNG mã hóa trực tiếp bằng ElGamal (chi phí rất lớn so với AES) -
/// xem <see cref="HybridEncryption"/>.
/// </summary>
public static class ElGamal
{
    // RFC 3526, nhóm MODP 2048-bit (id 14). p là số nguyên tố an toàn: p = 2q + 1 với q cũng nguyên tố.
    private const string PHex =
        "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    public static readonly BigInteger P =
        BigInteger.Parse(PHex, System.Globalization.NumberStyles.HexNumber);

    public static readonly BigInteger Q = (P - 1) / 2; // bậc nhóm con nguyên tố
    public static readonly BigInteger G = 2;

    /// <summary>Số byte của một phần tử nhóm (256 byte cho p 2048-bit) - dùng để mã hóa (c1,c2) cố định độ dài.</summary>
    public const int ElementSize = 256;

    /// <summary>Số byte dữ liệu thô tối đa nhồi được vào một khối (dành 1 byte đệm đầu + an toàn dưới bit-length của p).</summary>
    public const int MaxBlockPayload = ElementSize - 2;

    /// <summary>Sinh cặp khóa: x ngẫu nhiên trong [2, q-1], y = g^x mod p.</summary>
    public static ElGamalKeyPair GenerateKeyPair()
    {
        BigInteger x;
        do { x = BigIntUtil.RandomBits(320) % (Q - 2) + 2; } while (x < 2);
        BigInteger y = BigInteger.ModPow(G, x, P);
        return new ElGamalKeyPair { PublicKeyY = y, PrivateKeyX = x };
    }

    /// <summary>Mã hóa một số nguyên m (0 &lt; m &lt; p) bằng khóa công khai y của người nhận.</summary>
    public static ElGamalBlock EncryptRaw(BigInteger m, BigInteger publicKeyY)
    {
        BigInteger k;
        do { k = BigIntUtil.RandomBits(320) % (Q - 2) + 2; } while (k < 2);
        BigInteger c1 = BigInteger.ModPow(G, k, P);
        BigInteger s = BigInteger.ModPow(publicKeyY, k, P);
        BigInteger c2 = (m * s) % P;
        return new ElGamalBlock(c1, c2);
    }

    /// <summary>Giải mã một khối về lại số nguyên m bằng khóa riêng x.</summary>
    public static BigInteger DecryptRaw(ElGamalBlock block, BigInteger privateKeyX)
    {
        BigInteger s = BigInteger.ModPow(block.C1, privateKeyX, P);
        BigInteger sInv = BigIntUtil.ModInverse(s, P);
        return (block.C2 * sInv) % P;
    }

    /// <summary>
    /// Mã hóa một mảng byte tuỳ ý (điển hình: khóa phiên AES 32 byte, hoặc tin nhắn ngắn) bằng cách
    /// chia thành các khối &lt;= MaxBlockPayload byte, mỗi khối đệm 1 byte 0x01 ở đầu để đảm bảo m &gt; 0
    /// và giữ nguyên độ dài dữ liệu gốc (kể cả byte 0 ở đầu). Mỗi khối sinh ra 2*ElementSize byte.
    /// </summary>
    public static byte[] Encrypt(byte[] plaintext, BigInteger publicKeyY)
    {
        int blockCount = Math.Max(1, (plaintext.Length + MaxBlockPayload - 1) / MaxBlockPayload);
        using var out_ = new MemoryStream();
        for (int i = 0; i < blockCount; i++)
        {
            int offset = i * MaxBlockPayload;
            int len = Math.Min(MaxBlockPayload, plaintext.Length - offset);
            if (len < 0) len = 0;
            var chunk = new byte[len + 1];
            chunk[0] = 0x01; // byte đánh dấu đảm bảo m >= 1
            Array.Copy(plaintext, offset, chunk, 1, len);

            var m = BigIntUtil.FromBytes(chunk);
            var block = EncryptRaw(m, publicKeyY);
            out_.Write(BigIntUtil.ToFixed(block.C1, ElementSize));
            out_.Write(BigIntUtil.ToFixed(block.C2, ElementSize));
        }
        return out_.ToArray();
    }

    /// <summary>Giải mã dữ liệu được tạo bởi <see cref="Encrypt"/>.</summary>
    public static byte[] Decrypt(byte[] ciphertext, BigInteger privateKeyX)
    {
        if (ciphertext.Length % (2 * ElementSize) != 0)
            throw new ArgumentException("Độ dài bản mã ElGamal không hợp lệ.");

        using var out_ = new MemoryStream();
        for (int off = 0; off < ciphertext.Length; off += 2 * ElementSize)
        {
            var c1 = BigIntUtil.FromBytes(ciphertext[off..(off + ElementSize)]);
            var c2 = BigIntUtil.FromBytes(ciphertext[(off + ElementSize)..(off + 2 * ElementSize)]);
            var m = DecryptRaw(new ElGamalBlock(c1, c2), privateKeyX);
            var mb = BigIntUtil.ToBytes(m);
            if (mb.Length == 0 || mb[0] != 0x01)
                throw new CryptographicUnwrapException("Đệm ElGamal không hợp lệ - dữ liệu có thể đã bị hỏng hoặc sai khóa.");
            out_.Write(mb, 1, mb.Length - 1);
        }
        return out_.ToArray();
    }
}

/// <summary>Lỗi khi giải mã/giải gói dữ liệu (đệm sai, chữ ký sai, v.v.).</summary>
public sealed class CryptographicUnwrapException : Exception
{
    public CryptographicUnwrapException(string message) : base(message) { }
}
