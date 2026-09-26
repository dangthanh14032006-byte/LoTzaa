using System.Security.Cryptography;

namespace SecureChat.Core.Crypto;

public sealed class RsaKeyPair
{
    public required byte[] PublicKey { get; init; }   // SubjectPublicKeyInfo (DER)
    public required byte[] PrivateKey { get; init; }  // PKCS#8 (DER)
}

public static class RsaCipher
{
    public const int KeySizeBits = 2048;
    public const string AlgorithmName = "RSA-OAEP-SHA256";
    private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

    public static RsaKeyPair GenerateKeyPair()
    {
        using var rsa = RSA.Create(KeySizeBits);
        return new RsaKeyPair
        {
            PublicKey = rsa.ExportSubjectPublicKeyInfo(),
            PrivateKey = rsa.ExportPkcs8PrivateKey(),
        };
    }

    public static byte[] Encrypt(byte[] data, byte[] publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
        return rsa.Encrypt(data, Padding);   // tối đa 190 byte, khóa AES 32 byte là đủ
    }

    public static byte[] Decrypt(byte[] cipher, byte[] privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        return rsa.Decrypt(cipher, Padding);
    }
}