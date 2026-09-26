using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecureChat.Core.Crypto;

/// <summary>Định dạng file lưu khóa riêng trên đĩa của client (đã mã hóa bằng mật khẩu người dùng).</summary>
internal sealed class KeyFile
{
    public string Username { get; set; } = "";
    public string PublicKeyB64 { get; set; } = "";
    public string SaltB64 { get; set; } = "";
    public int Iterations { get; set; }
    /// <summary>Khóa riêng x, đã mã hóa AES-256-GCM bằng khóa dẫn xuất PBKDF2(password, salt).</summary>
    public string EncryptedPrivateKeyB64 { get; set; } = "";

    // RSA
    public string RsaPublicKeyB64 { get; set; } = "";
    public string EncryptedRsaPrivateKeyB64 { get; set; } = "";
}

/// <summary>
/// Quản lý khóa phía client: sinh cặp khóa ElGamal, lưu xuống đĩa với khóa riêng được
/// mã hóa bằng mật khẩu (PBKDF2-SHA256 dẫn xuất khóa AES, rồi AES-256-GCM mã hóa x).
/// Khóa riêng KHÔNG BAO GIỜ rời máy client dưới dạng bản rõ, kể cả khi đăng ký với server
/// (server chỉ nhận khóa công khai y).
/// </summary>
public static class KeyStore
{
    private const int Pbkdf2Iterations = 200_000;

    public static string DefaultPath(string username, string dir) =>
        Path.Combine(dir, $"{username}.key.json");

    /// <summary>Sinh cặp khóa mới và lưu xuống đĩa, bảo vệ bằng mật khẩu.</summary>
    public static ElGamalKeyPair CreateAndSave(string username, string password, string path)
    {
        var eg = ElGamal.GenerateKeyPair();
        var keys = new ElGamalKeyPair
        {
            PublicKeyY = eg.PublicKeyY,
            PrivateKeyX = eg.PrivateKeyX,
            Rsa = RsaCipher.GenerateKeyPair(),
        };
        Save(username, keys, password, path);
        return keys;
    }

    public static void Save(string username, ElGamalKeyPair keys, string password, string path)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = HashUtil.Pbkdf2(password, salt, Pbkdf2Iterations, AesGcmCipher.KeySize);
        var privBytes = BigIntUtil.ToBytes(keys.PrivateKeyX);
        var encrypted = AesGcmCipher.Encrypt(kek, privBytes);

        var file = new KeyFile
        {
            Username = username,
            PublicKeyB64 = BigIntUtil.ToB64(keys.PublicKeyY),
            SaltB64 = Convert.ToBase64String(salt),
            Iterations = Pbkdf2Iterations,
            EncryptedPrivateKeyB64 = Convert.ToBase64String(encrypted),

            // MỚI
            RsaPublicKeyB64 = keys.Rsa is null ? "" : Convert.ToBase64String(keys.Rsa.PublicKey),
            EncryptedRsaPrivateKeyB64 = keys.Rsa is null ? "" :
        Convert.ToBase64String(AesGcmCipher.Encrypt(kek, keys.Rsa.PrivateKey)),
        };

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, JsonSerializer.Serialize(file));
    }

    /// <summary>Nạp lại cặp khóa từ đĩa. Ném CryptographicException nếu sai mật khẩu.</summary>
    public static ElGamalKeyPair Load(string password, string path)
    {
        var file = JsonSerializer.Deserialize<KeyFile>(File.ReadAllText(path))
                   ?? throw new InvalidDataException("File khóa không hợp lệ.");

        var salt = Convert.FromBase64String(file.SaltB64);
        var kek = HashUtil.Pbkdf2(password, salt, file.Iterations, AesGcmCipher.KeySize);
        var encrypted = Convert.FromBase64String(file.EncryptedPrivateKeyB64);

        byte[] privBytes;
        try
        {
            privBytes = AesGcmCipher.Decrypt(kek, encrypted); // ném lỗi nếu sai mật khẩu (tag GCM không khớp)
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Sai mật khẩu hoặc file khóa đã bị hỏng.");
        }

        var x = BigIntUtil.FromBytes(privBytes);
        var y = BigIntUtil.FromB64(file.PublicKeyB64);
        RsaKeyPair? rsa = null;
        if (!string.IsNullOrEmpty(file.RsaPublicKeyB64))
        {
            var rsaPriv = AesGcmCipher.Decrypt(kek, Convert.FromBase64String(file.EncryptedRsaPrivateKeyB64));
            rsa = new RsaKeyPair
            {
                PublicKey = Convert.FromBase64String(file.RsaPublicKeyB64),
                PrivateKey = rsaPriv,
            };
        }
        return new ElGamalKeyPair { PrivateKeyX = x, PublicKeyY = y, Rsa = rsa };
    }

    public static bool Exists(string path) => File.Exists(path);

    public static BigInteger ReadPublicKeyOnly(string path)
    {
        var file = JsonSerializer.Deserialize<KeyFile>(File.ReadAllText(path))
                   ?? throw new InvalidDataException("File khóa không hợp lệ.");
        return BigIntUtil.FromB64(file.PublicKeyB64);
    }
}
