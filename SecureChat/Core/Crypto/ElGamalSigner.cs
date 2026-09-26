using System.Numerics;

namespace SecureChat.Core.Crypto;

/// <summary>Chữ ký số ElGamal: cặp (r, s) trên cùng nhóm (p, g) với khóa ElGamal.</summary>
public readonly struct ElGamalSignature
{
    public BigInteger R { get; }
    public BigInteger S { get; }
    public ElGamalSignature(BigInteger r, BigInteger s) { R = r; S = s; }

    public byte[] ToBytes()
    {
        var buf = new byte[2 * ElGamal.ElementSize];
        Array.Copy(BigIntUtil.ToFixed(R, ElGamal.ElementSize), 0, buf, 0, ElGamal.ElementSize);
        Array.Copy(BigIntUtil.ToFixed(S, ElGamal.ElementSize), 0, buf, ElGamal.ElementSize, ElGamal.ElementSize);
        return buf;
    }

    public static ElGamalSignature FromBytes(byte[] data)
    {
        if (data.Length != 2 * ElGamal.ElementSize) throw new ArgumentException("Độ dài chữ ký không hợp lệ.");
        var r = BigIntUtil.FromBytes(data[..ElGamal.ElementSize]);
        var s = BigIntUtil.FromBytes(data[ElGamal.ElementSize..]);
        return new ElGamalSignature(r, s);
    }
}

/// <summary>
/// Sơ đồ chữ ký số ElGamal cổ điển (không phải DSA): ký trên băm SHA-256 của dữ liệu.
/// Dùng để mỗi người dùng tự xác thực (non-repudiation) các gói tin gửi đi, độc lập với
/// HMAC dùng cho toàn vẹn kênh (xem <see cref="HashUtil.HmacSha256"/>).
/// </summary>
public static class ElGamalSigner
{
    /// <summary>Ký băm SHA-256 của dữ liệu bằng khóa riêng x. k được chọn ngẫu nhiên, nguyên tố cùng nhau với p-1.</summary>
    public static ElGamalSignature Sign(byte[] data, BigInteger privateKeyX)
    {
        BigInteger p = ElGamal.P, g = ElGamal.G, pm1 = p - 1;
        BigInteger h = BigIntUtil.FromBytes(HashUtil.Sha256(data)) % pm1;

        while (true)
        {
            BigInteger k;
            do { k = BigIntUtil.RandomBits(264) % (pm1 - 2) + 2; } while (k < 2 || BigInteger.GreatestCommonDivisor(k, pm1) != 1);

            BigInteger r = BigInteger.ModPow(g, k, p);
            BigInteger kInv = BigIntUtil.ModInverse(k, pm1);
            BigInteger s = (((h - privateKeyX * r) % pm1 + pm1) * kInv) % pm1;
            if (s == 0) continue; // xác suất cực nhỏ, thử lại cho an toàn
            return new ElGamalSignature(r, s);
        }
    }

    /// <summary>Xác minh chữ ký: kiểm tra y^r * r^s mod p == g^H(data) mod p.</summary>
    public static bool Verify(byte[] data, ElGamalSignature sig, BigInteger publicKeyY)
    {
        BigInteger p = ElGamal.P, g = ElGamal.G, pm1 = p - 1;
        if (sig.R <= 0 || sig.R >= p || sig.S <= 0 || sig.S >= pm1) return false;

        BigInteger h = BigIntUtil.FromBytes(HashUtil.Sha256(data)) % pm1;
        BigInteger left = (BigInteger.ModPow(publicKeyY, sig.R, p) * BigInteger.ModPow(sig.R, sig.S, p)) % p;
        BigInteger right = BigInteger.ModPow(g, h, p);
        return left == right;
    }
}
