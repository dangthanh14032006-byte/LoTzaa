using System.Security.Cryptography;

namespace SecureChat.Core.Crypto;

/// <summary>
/// AES-256-GCM: mã hóa đối xứng nội dung tin nhắn bằng khóa phiên. GCM cung cấp cả bí mật
/// lẫn toàn vẹn/xác thực (AEAD) trong một bước, dùng thẻ xác thực (tag) 128-bit.
/// Định dạng gói: [nonce 12 byte][ciphertext][tag 16 byte].
/// </summary>
public static class AesGcmCipher
{
    public const int KeySize = 32;   // AES-256
    public const int NonceSize = 12; // khuyến nghị chuẩn GCM
    public const int TagSize = 16;

    public static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(KeySize);

    /// <summary>Mã hóa. aad (associated data) tuỳ chọn được xác thực nhưng không mã hóa (vd: id người gửi/nhận, timestamp).</summary>
    public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[]? aad = null)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        var result = new byte[NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);
        return result;
    }

    /// <summary>Giải mã và xác minh tag. Ném CryptographicException nếu dữ liệu bị sửa đổi hoặc sai khóa.</summary>
    public static byte[] Decrypt(byte[] key, byte[] packet, byte[]? aad = null)
    {
        if (packet.Length < NonceSize + TagSize)
            throw new ArgumentException("Gói AES-GCM quá ngắn.");

        var nonce = packet[..NonceSize];
        int cLen = packet.Length - NonceSize - TagSize;
        var ciphertext = packet[NonceSize..(NonceSize + cLen)];
        var tag = packet[(NonceSize + cLen)..];
        var plaintext = new byte[cLen];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad); // ném lỗi nếu tag sai (dữ liệu bị giả mạo)
        return plaintext;
    }
}
