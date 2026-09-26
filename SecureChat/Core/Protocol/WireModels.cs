using System.Numerics;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.Protocol;

/// <summary>Loại gói tin trao đổi giữa client và server, một gói JSON trên mỗi dòng (newline-delimited).</summary>
public enum PacketType
{
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    ListUsersRequest, ListUsersResponse,
    PublicKeyRequest, PublicKeyResponse,
    ChatSend,       // client -> server: gửi envelope đã mã hóa cho người nhận
    ChatIncoming,   // server -> client: chuyển tiếp envelope tới người nhận (đang online)
    HistoryRequest, HistoryResponse,
    Error,
}

/// <summary>Phong bì truyền tải chung; Payload là JSON của DTO tương ứng với Type.</summary>
public sealed class Packet
{
    public PacketType Type { get; set; }
    public string PayloadJson { get; set; } = "";
}

public sealed class RegisterRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";

    // ElGamal public key
    public string PublicKeyB64 { get; set; } = "";

    // RSA-2048 public key
    public string RsaPublicKeyB64 { get; set; } = "";
}
public sealed class RegisterResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
}

public sealed class LoginRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public sealed class LoginResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
}

public sealed class UserSummary
{
    public string Username { get; set; } = "";
    public bool Online { get; set; }
}

public sealed class ListUsersResponse
{
    public List<UserSummary> Users { get; set; } = new();
}

public sealed class PublicKeyRequest
{
    public string Username { get; set; } = "";
}

public sealed class PublicKeyResponse
{
    public bool Found { get; set; }

    public string Username { get; set; } = "";

    // ElGamal public key
    public string PublicKeyB64 { get; set; } = "";

    // RSA public key
    public string RsaPublicKeyB64 { get; set; } = "";
}
/// <summary>Biểu diễn JSON-an toàn của EncryptedEnvelope (byte[] -> Base64).</summary>
public sealed class EnvelopeDto
{
    public string SenderId { get; set; } = "";
    public string ReceiverId { get; set; } = "";
    public long TimestampUnixMs { get; set; }
    public string WrappedSessionKeyB64 { get; set; } = "";
    public string WrappedSessionKeyRsaB64 { get; set; } = "";
    public string CiphertextB64 { get; set; } = "";
    public string Sha256Hex { get; set; } = "";
    public string Md5Hex { get; set; } = "";
    public string SignatureB64 { get; set; } = "";

    public static EnvelopeDto From(EncryptedEnvelope e) => new()
    {
        SenderId = e.SenderId,
        ReceiverId = e.ReceiverId,
        TimestampUnixMs = e.Timestamp.ToUnixTimeMilliseconds(),
        WrappedSessionKeyB64 = Convert.ToBase64String(e.WrappedSessionKey),
        WrappedSessionKeyRsaB64 =
    Convert.ToBase64String(e.WrappedSessionKeyRsa),
        CiphertextB64 = Convert.ToBase64String(e.Ciphertext),
        Sha256Hex = e.Sha256Hex,
        Md5Hex = e.Md5Hex,
        SignatureB64 = Convert.ToBase64String(e.Signature),
    };

    public EncryptedEnvelope ToEnvelope() => new()
    {
        SenderId = SenderId,
        ReceiverId = ReceiverId,
        Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(TimestampUnixMs),
        WrappedSessionKey = Convert.FromBase64String(WrappedSessionKeyB64),
        WrappedSessionKeyRsa =
    Convert.FromBase64String(WrappedSessionKeyRsaB64),
        Ciphertext = Convert.FromBase64String(CiphertextB64),
        Sha256Hex = Sha256Hex,
        Md5Hex = Md5Hex,
        Signature = Convert.FromBase64String(SignatureB64),
    };
}

public sealed class ChatSendRequest
{
    public EnvelopeDto Envelope { get; set; } = new();
}

public sealed class ChatIncoming
{
    public EnvelopeDto Envelope { get; set; } = new();
}

public sealed class HistoryRequest
{
    public string WithUsername { get; set; } = "";
}

public sealed class HistoryResponse
{
    public List<EnvelopeDto> Envelopes { get; set; } = new();
}

public sealed class ErrorMessage
{
    public string Message { get; set; } = "";
}