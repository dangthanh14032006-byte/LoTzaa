using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Crypto;

/// <summary>
/// Các hàm băm. SHA-256 / HMAC-SHA256 dùng cho các quyết định bảo mật (chữ ký, toàn vẹn, dẫn xuất khóa).
/// MD5 chỉ dùng làm checksum nhanh phát hiện lỗi truyền/lưu và để so sánh hiệu năng -
/// MD5 đã bị phá về khả năng chống va chạm nên KHÔNG được dùng để xác thực.
/// </summary>
public static class HashUtil
{
    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static byte[] Md5(byte[] data) => MD5.HashData(data);

    public static byte[] HmacSha256(byte[] key, byte[] data) => HMACSHA256.HashData(key, data);

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static string Md5Hex(string text) => Hex(Md5(Encoding.UTF8.GetBytes(text)));

    /// <summary>Dẫn xuất khóa từ mật khẩu bằng PBKDF2-HMAC-SHA256.</summary>
    public static byte[] Pbkdf2(string password, byte[] salt, int iterations, int outputLength)
        => Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, outputLength);

    /// <summary>Vân tay khóa công khai (SHA-256), dạng AA:BB:CC... để hai người đối chiếu qua kênh khác.</summary>
    public static string FingerprintSha256(BigInteger publicKey)
    {
        var h = Sha256(BigIntUtil.ToBytes(publicKey));
        return string.Join(":", h.Take(16).Select(b => b.ToString("X2")));
    }

    /// <summary>Vân tay ngắn (MD5) - chỉ để hiển thị/so sánh nhanh.</summary>
    public static string FingerprintMd5(BigInteger publicKey)
    {
        var h = Md5(BigIntUtil.ToBytes(publicKey));
        return string.Join(":", h.Select(b => b.ToString("X2")));
    }
}
