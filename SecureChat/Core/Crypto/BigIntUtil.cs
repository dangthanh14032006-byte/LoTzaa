using System.Numerics;
using System.Security.Cryptography;

namespace SecureChat.Core.Crypto;

/// <summary>Các hàm tiện ích cho số nguyên lớn dùng trong ElGamal.</summary>
public static class BigIntUtil
{
    public static byte[] ToBytes(BigInteger n) => n.ToByteArray(isUnsigned: true, isBigEndian: true);

    public static BigInteger FromBytes(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);

    /// <summary>Chuyển số thành mảng byte big-endian có độ dài cố định (đệm 0 phía trước).</summary>
    public static byte[] ToFixed(BigInteger n, int length)
    {
        var b = ToBytes(n);
        if (b.Length > length) throw new ArgumentException("Số quá lớn so với độ dài cố định.");
        var r = new byte[length];
        Buffer.BlockCopy(b, 0, r, length - b.Length, b.Length);
        return r;
    }

    public static string ToB64(BigInteger n) => Convert.ToBase64String(ToBytes(n));

    public static BigInteger FromB64(string s) => FromBytes(Convert.FromBase64String(s));

    /// <summary>Số ngẫu nhiên mật mã học trong [0, maxExclusive). Lấy dư 16 byte để độ lệch không đáng kể.</summary>
    public static BigInteger RandomBelow(BigInteger maxExclusive)
    {
        int len = ToBytes(maxExclusive).Length + 16;
        return FromBytes(RandomNumberGenerator.GetBytes(len)) % maxExclusive;
    }

    /// <summary>Số ngẫu nhiên mật mã học có tối đa <paramref name="bits"/> bit.</summary>
    public static BigInteger RandomBits(int bits)
    {
        int bytes = (bits + 7) / 8;
        var buf = RandomNumberGenerator.GetBytes(bytes);
        int extra = bytes * 8 - bits;
        if (extra > 0) buf[0] &= (byte)(0xFF >> extra);
        return FromBytes(buf);
    }

    /// <summary>Nghịch đảo modulo bằng thuật toán Euclid mở rộng (a phải nguyên tố cùng nhau với m).</summary>
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, x0 = 0, x1 = 1;
        a %= m;
        if (a.Sign < 0) a += m;
        if (a.IsZero) throw new ArithmeticException("Không tồn tại nghịch đảo modulo (a = 0).");
        if (m.IsOne) return 0;

        while (a > 1)
        {
            if (m.IsZero) throw new ArithmeticException("Không tồn tại nghịch đảo modulo (gcd > 1).");
            BigInteger q = a / m;
            BigInteger t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1.Sign < 0) x1 += m0;
        return x1;
    }
}
