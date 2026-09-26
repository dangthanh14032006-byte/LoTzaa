using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SecureChat.Core.Crypto;

/// <summary>
/// Thước đo hiệu năng và kích thước của một lần mã hóa/giải mã.
/// </summary>
public sealed class CryptoMetrics
{
    public double EncryptMs { get; init; }
    public double DecryptMs { get; init; }
    public int PlaintextBytes { get; init; }
    public int CiphertextBytes { get; init; }

    public double Overhead =>
        PlaintextBytes == 0
            ? 0
            : (double)CiphertextBytes / PlaintextBytes;

    public override string ToString() =>
        $"mã hóa={EncryptMs:F3}ms, giải mã={DecryptMs:F3}ms, " +
        $"gốc={PlaintextBytes}B, mã hóa={CiphertextBytes}B, " +
        $"hệ số phình={Overhead:F2}x";
}

/// <summary>
/// Gói tin đã mã hóa hoàn chỉnh.
/// 
/// Mô hình hybrid:
/// - AES-256-GCM: mã hóa nội dung tin nhắn.
/// - RSA-OAEP-SHA256: mã hóa khóa AES phiên.
/// - ElGamal: giữ lại để ký số gói tin.
/// - SHA-256: kiểm tra toàn vẹn.
/// - MD5: checksum tham khảo.
/// </summary>
public sealed class EncryptedEnvelope
{
    public required string SenderId { get; init; }
    public required string ReceiverId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// Khóa AES phiên được mã hóa bằng ElGamal.
    /// Giữ lại để bảo toàn cấu trúc cũ và phục vụ so sánh.
    /// </summary>
    public required byte[] WrappedSessionKey { get; init; }

    /// <summary>
    /// Khóa AES phiên được mã hóa bằng RSA-OAEP-SHA256.
    /// </summary>
    public byte[]? WrappedSessionKeyRsa { get; init; }

    /// <summary>
    /// Nội dung tin nhắn AES-256-GCM:
    /// [nonce | ciphertext | tag]
    /// </summary>
    public required byte[] Ciphertext { get; init; }

    /// <summary>
    /// SHA-256 của bản rõ.
    /// </summary>
    public required string Sha256Hex { get; init; }

    /// <summary>
    /// MD5 của bản rõ - chỉ dùng tham khảo.
    /// </summary>
    public required string Md5Hex { get; init; }

    /// <summary>
    /// Chữ ký số ElGamal của người gửi.
    /// </summary>
    public required byte[] Signature { get; init; }

    public CryptoMetrics? Metrics { get; init; }

    /// <summary>
    /// Dữ liệu chuẩn hóa dùng để tạo và xác minh chữ ký.
    /// </summary>
    public byte[] BuildSignedPayload()
    {
        using var ms = new MemoryStream();

        void WriteStr(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);

            WriteInt(b.Length);

            ms.Write(
                b,
                0,
                b.Length);
        }

        void WriteInt(int v)
        {
            var bytes = BitConverter.GetBytes(v);

            ms.Write(
                bytes,
                0,
                bytes.Length);
        }

        void WriteBytes(byte[] b)
        {
            WriteInt(b.Length);

            ms.Write(
                b,
                0,
                b.Length);
        }

        WriteStr(SenderId);

        WriteStr(ReceiverId);

        var timestampBytes =
            BitConverter.GetBytes(
                Timestamp.ToUnixTimeMilliseconds());

        ms.Write(
            timestampBytes,
            0,
            timestampBytes.Length);

        // ElGamal wrapped key
        WriteBytes(WrappedSessionKey);

        // RSA wrapped key
        if (WrappedSessionKeyRsa != null)
        {
            WriteBytes(WrappedSessionKeyRsa);
        }

        // AES ciphertext
        WriteBytes(Ciphertext);

        // SHA-256
        WriteStr(Sha256Hex);

        return ms.ToArray();
    }
}

/// <summary>
/// Kết quả sau khi giải mã và xác minh.
/// </summary>
public sealed class DecryptedMessage
{
    public required string PlaintextUtf8 { get; init; }

    public required bool SignatureValid { get; init; }

    public required bool Sha256Match { get; init; }

    public required bool Md5Match { get; init; }

    public required CryptoMetrics Metrics { get; init; }

    public bool FullyTrusted =>
        SignatureValid && Sha256Match;
}

/// <summary>
/// Điều phối AES-256-GCM + RSA-OAEP-SHA256 + ElGamal
/// + SHA-256/MD5 + chữ ký số.
/// </summary>
public static class HybridEncryption
{
    /// <summary>
    /// Mã hóa tin nhắn.
    /// 
    /// AES dùng để mã hóa nội dung.
    /// RSA dùng để mã hóa khóa AES phiên.
    /// ElGamal vẫn được dùng để ký số.
    /// </summary>
    public static EncryptedEnvelope Encrypt(
        string senderId,
        ElGamalKeyPair senderKeys,
        string receiverId,
        BigInteger receiverPublicKey,
        byte[] receiverRsaPublicKey,
        string plaintext)
    {
        var sw = Stopwatch.StartNew();

        // =====================================================
        // 1. Chuyển bản rõ thành byte
        // =====================================================

        var plainBytes =
            Encoding.UTF8.GetBytes(plaintext);

        // =====================================================
        // 2. Sinh khóa AES phiên
        // =====================================================

        var sessionKey =
            AesGcmCipher.GenerateKey();

        // =====================================================
        // 3. AES-256-GCM mã hóa nội dung
        // =====================================================

        var ciphertext =
            AesGcmCipher.Encrypt(
                sessionKey,
                plainBytes);

        // =====================================================
        // 4. ElGamal mã hóa khóa AES
        //    Giữ lại để bảo toàn cơ chế cũ
        // =====================================================

        var wrappedKey =
            ElGamal.Encrypt(
                sessionKey,
                receiverPublicKey);

        // =====================================================
        // 5. RSA-OAEP-SHA256 mã hóa khóa AES
        // =====================================================

        var wrappedKeyRsa =
            RsaCipher.Encrypt(
                sessionKey,
                receiverRsaPublicKey);

        // =====================================================
        // 6. Hash
        // =====================================================

        var sha256Hex =
            HashUtil.Hex(
                HashUtil.Sha256(
                    plainBytes));

        var md5Hex =
            HashUtil.Hex(
                HashUtil.Md5(
                    plainBytes));

        // =====================================================
        // 7. Tạo envelope tạm để ký
        // =====================================================

        var envelopeStub =
            new EncryptedEnvelope
            {
                SenderId = senderId,

                ReceiverId = receiverId,

                Timestamp =
                    DateTimeOffset.UtcNow,

                WrappedSessionKey =
                    wrappedKey,

                WrappedSessionKeyRsa =
                    wrappedKeyRsa,

                Ciphertext =
                    ciphertext,

                Sha256Hex =
                    sha256Hex,

                Md5Hex =
                    md5Hex,

                Signature =
                    Array.Empty<byte>()
            };

        // =====================================================
        // 8. Ký số bằng ElGamal
        // =====================================================

        var toSign =
            HashUtil.Sha256(
                envelopeStub.BuildSignedPayload());

        var signature =
            ElGamalSigner.Sign(
                toSign,
                senderKeys.PrivateKeyX)
            .ToBytes();

        sw.Stop();

        // =====================================================
        // 9. Tính kích thước
        // =====================================================

        int cipherTotal =
            wrappedKey.Length +
            wrappedKeyRsa.Length +
            ciphertext.Length +
            signature.Length +
            32 +
            16;

        var metrics =
            new CryptoMetrics
            {
                EncryptMs =
                    sw.Elapsed.TotalMilliseconds,

                DecryptMs = 0,

                PlaintextBytes =
                    plainBytes.Length,

                CiphertextBytes =
                    cipherTotal
            };

        // =====================================================
        // 10. Trả envelope hoàn chỉnh
        // =====================================================

        return new EncryptedEnvelope
        {
            SenderId =
                senderId,

            ReceiverId =
                receiverId,

            Timestamp =
                envelopeStub.Timestamp,

            WrappedSessionKey =
                wrappedKey,

            WrappedSessionKeyRsa =
                wrappedKeyRsa,

            Ciphertext =
                ciphertext,

            Sha256Hex =
                sha256Hex,

            Md5Hex =
                md5Hex,

            Signature =
                signature,

            Metrics =
                metrics
        };
    }

    /// <summary>
    /// Giải mã:
    /// 1. Xác minh chữ ký ElGamal.
    /// 2. Dùng RSA private key để mở khóa AES.
    /// 3. AES-256-GCM giải mã nội dung.
    /// 4. Kiểm tra SHA-256 và MD5.
    /// </summary>
    public static DecryptedMessage Decrypt(
        EncryptedEnvelope envelope,
        ElGamalKeyPair receiverKeys,
        BigInteger senderPublicKey)
    {
        var sw =
            Stopwatch.StartNew();

        // =====================================================
        // 1. Kiểm tra chữ ký ElGamal
        // =====================================================

        var toSign =
            HashUtil.Sha256(
                envelope.BuildSignedPayload());

        bool sigValid =
            ElGamalSigner.Verify(
                toSign,
                ElGamalSignature.FromBytes(
                    envelope.Signature),
                senderPublicKey);

        // =====================================================
        // 2. Kiểm tra RSA private key
        // =====================================================

        if (receiverKeys.Rsa is null)
        {
            throw new CryptographicException(
                "Không tìm thấy RSA private key của người nhận.");
        }

        // =====================================================
        // 3. RSA giải mã khóa AES
        // =====================================================

        var sessionKey =
            RsaCipher.Decrypt(
                envelope.WrappedSessionKeyRsa,
                receiverKeys.Rsa.PrivateKey);

        // =====================================================
        // 4. AES-256-GCM giải mã nội dung
        // =====================================================

        var plainBytes =
            AesGcmCipher.Decrypt(
                sessionKey,
                envelope.Ciphertext);

        // =====================================================
        // 5. Kiểm tra SHA-256
        // =====================================================

        bool shaMatch =
            HashUtil.Hex(
                HashUtil.Sha256(
                    plainBytes))
            == envelope.Sha256Hex;

        // =====================================================
        // 6. Kiểm tra MD5
        // =====================================================

        bool md5Match =
            HashUtil.Hex(
                HashUtil.Md5(
                    plainBytes))
            == envelope.Md5Hex;

        sw.Stop();

        // =====================================================
        // 7. Metrics
        // =====================================================

        int cipherTotal =
            envelope.WrappedSessionKey.Length +
            envelope.WrappedSessionKeyRsa.Length +
            envelope.Ciphertext.Length +
            envelope.Signature.Length +
            32 +
            16;

        var metrics =
            new CryptoMetrics
            {
                EncryptMs = 0,

                DecryptMs =
                    sw.Elapsed.TotalMilliseconds,

                PlaintextBytes =
                    plainBytes.Length,

                CiphertextBytes =
                    cipherTotal
            };

        // =====================================================
        // 8. Kết quả
        // =====================================================

        return new DecryptedMessage
        {
            PlaintextUtf8 =
                Encoding.UTF8.GetString(
                    plainBytes),

            SignatureValid =
                sigValid,

            Sha256Match =
                shaMatch,

            Md5Match =
                md5Match,

            Metrics =
                metrics
        };
    }
}