using System.Numerics;
using System.Text;
using SecureChat.Core.Crypto;

namespace SecureChat.Web.Services;

public sealed class GroupEnvelope
{
    public required string GroupId { get; init; }
    public required string SenderId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required byte[] Ciphertext { get; init; }
    public required string Sha256Hex { get; init; }
    public required byte[] Signature { get; init; }
    public required Dictionary<string, byte[]> WrappedKeys { get; init; }
}

public static class GroupEncryption
{
    public static GroupEnvelope Encrypt(
        string groupId, string senderId, ElGamalKeyPair senderKeys,
        Dictionary<string, BigInteger> memberPublicKeys, string plaintext)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var sessionKey = AesGcmCipher.GenerateKey();
        var ciphertext = AesGcmCipher.Encrypt(sessionKey, plainBytes);
        var sha256Hex = HashUtil.Hex(HashUtil.Sha256(plainBytes));

        var wrapped = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in memberPublicKeys)
            wrapped[pair.Key] = ElGamal.Encrypt(sessionKey, pair.Value);

        var timestamp = DateTimeOffset.UtcNow;
        var toSign = HashUtil.Sha256(BuildSignedPayload(groupId, senderId, timestamp, sha256Hex, ciphertext));
        var signature = ElGamalSigner.Sign(toSign, senderKeys.PrivateKeyX).ToBytes();

        return new GroupEnvelope
        {
            GroupId = groupId,
            SenderId = senderId,
            Timestamp = timestamp,
            Ciphertext = ciphertext,
            Sha256Hex = sha256Hex,
            Signature = signature,
            WrappedKeys = wrapped
        };
    }

    public static (string plaintext, bool sigValid, bool shaMatch) Decrypt(
        GroupEnvelope envelope, string myUsername, ElGamalKeyPair myKeys, BigInteger senderPublicKey)
    {
        if (!envelope.WrappedKeys.TryGetValue(myUsername, out var wrappedKey))
            throw new InvalidOperationException("Bạn không phải thành viên nhận tin nhắn này.");

        var toSign = HashUtil.Sha256(BuildSignedPayload(
            envelope.GroupId, envelope.SenderId, envelope.Timestamp, envelope.Sha256Hex, envelope.Ciphertext));
        bool sigValid = ElGamalSigner.Verify(toSign, ElGamalSignature.FromBytes(envelope.Signature), senderPublicKey);

        var sessionKey = ElGamal.Decrypt(wrappedKey, myKeys.PrivateKeyX);
        var plainBytes = AesGcmCipher.Decrypt(sessionKey, envelope.Ciphertext);
        bool shaMatch = HashUtil.Hex(HashUtil.Sha256(plainBytes)) == envelope.Sha256Hex;

        return (Encoding.UTF8.GetString(plainBytes), sigValid, shaMatch);
    }

    private static byte[] BuildSignedPayload(
        string groupId, string senderId, DateTimeOffset ts, string sha256Hex, byte[] ciphertext)
    {
        using var ms = new MemoryStream();
        void WriteStr(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);
            ms.Write(BitConverter.GetBytes(b.Length));
            ms.Write(b);
        }
        WriteStr(groupId);
        WriteStr(senderId);
        ms.Write(BitConverter.GetBytes(ts.ToUnixTimeMilliseconds()));
        WriteStr(sha256Hex);
        ms.Write(BitConverter.GetBytes(ciphertext.Length));
        ms.Write(ciphertext);
        return ms.ToArray();
    }
}