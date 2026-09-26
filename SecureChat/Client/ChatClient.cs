using System.Net.Sockets;
using System.Numerics;
using SecureChat.Core.Crypto;
using SecureChat.Core.Protocol;
using System.Threading.Channels;

namespace SecureChat.Client;

/// <summary>
/// Sự kiện có tin nhắn mới đến sau khi giải mã.
/// </summary>
public sealed record IncomingChatEvent(
    string FromUsername,
    DecryptedMessage Message,
    DateTimeOffset Timestamp);

public sealed class ChatClient : IAsyncDisposable
{
    private readonly TcpClient _tcp = new();
    private NetworkStream? _stream;
    private readonly StreamReadBuffer _readBuffer = new();

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly object _pendingLock = new();

    private CancellationTokenSource? _readLoopCts;

    public string? Username { get; private set; }
    public ElGamalKeyPair? MyKeys { get; private set; }

    private readonly Dictionary<string, BigInteger> _peerKeyCache = new();
    private readonly Dictionary<string, byte[]> _peerRsaKeyCache = new();
    public event Action<IncomingChatEvent>? OnIncomingMessage;
    public event Action<string>? OnServerError;

    // Hàng đợi tin nhắn đến.
    // Không xử lý trực tiếp trong ReadLoopAsync để tránh deadlock
    // khi cần gọi GetPeerPublicKeyAsync().
    private readonly Channel<EnvelopeDto> _incomingQueue =
        Channel.CreateUnbounded<EnvelopeDto>();

    // Các request đang chờ response
    private readonly Dictionary<
        PacketType,
        Queue<TaskCompletionSource<Packet>>> _waiters = new();

    // =========================================================
    // CONNECT
    // =========================================================

    public async Task ConnectAsync(string host, int port)
    {
        await _tcp.ConnectAsync(host, port);

        _stream = _tcp.GetStream();

        _readLoopCts = new CancellationTokenSource();

        _ = ReadLoopAsync(_readLoopCts.Token);
        _ = IncomingProcessingLoopAsync(_readLoopCts.Token);
    }

    // =========================================================
    // XỬ LÝ TIN NHẮN ĐẾN
    // =========================================================

    private async Task IncomingProcessingLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var envelope in
                _incomingQueue.Reader.ReadAllAsync(ct))
            {
                await HandleIncomingAsync(envelope);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            OnServerError?.Invoke(
                $"Lỗi xử lý tin nhắn đến: {ex.Message}");
        }
    }

    // =========================================================
    // READ LOOP
    // =========================================================

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await WireCodec.ReadPacketAsync(
                    _stream!,
                    _readBuffer,
                    ct);

                if (packet == null)
                    break;

                // Tin nhắn đến realtime
                if (packet.Type == PacketType.ChatIncoming)
                {
                    var incoming =
                        WireCodec.ReadPayload<ChatIncoming>(packet);

                    await _incomingQueue.Writer.WriteAsync(
                        incoming.Envelope,
                        ct);

                    continue;
                }

                TaskCompletionSource<Packet>? waiter = null;

                lock (_pendingLock)
                {
                    if (_waiters.TryGetValue(
                        packet.Type,
                        out var queue) &&
                        queue.Count > 0)
                    {
                        waiter = queue.Dequeue();
                    }
                }

                waiter?.TrySetResult(packet);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            OnServerError?.Invoke(
                $"Mất kết nối tới server: {ex.Message}");
        }
    }

    // =========================================================
    // WAIT RESPONSE
    // =========================================================

    private Task<Packet> WaitForAsync(PacketType type)
    {
        var tcs =
            new TaskCompletionSource<Packet>(
                TaskCreationOptions.RunContinuationsAsynchronously);

        lock (_pendingLock)
        {
            if (!_waiters.TryGetValue(type, out var queue))
            {
                queue = new Queue<TaskCompletionSource<Packet>>();
                _waiters[type] = queue;
            }

            queue.Enqueue(tcs);
        }

        return tcs.Task;
    }

    // =========================================================
    // REQUEST / RESPONSE
    // =========================================================

    private async Task<TResp> RequestAsync<TReq, TResp>(
        PacketType reqType,
        TReq req,
        PacketType respType)
    {
        var waitTask = WaitForAsync(respType);

        await SendAsync(reqType, req);

        var packet = await waitTask;

        return WireCodec.ReadPayload<TResp>(packet);
    }

    // =========================================================
    // SEND PACKET
    // =========================================================

    private async Task SendAsync<T>(
        PacketType type,
        T payload)
    {
        await _writeLock.WaitAsync();

        try
        {
            await WireCodec.WritePacketAsync(
                _stream!,
                WireCodec.MakePacket(type, payload));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // =========================================================
    // REGISTER
    // =========================================================

    public async Task<(bool ok, string message)> RegisterAsync(
        string username,
        string password,
        string keyDir)
    {
        var path =
            KeyStore.DefaultPath(username, keyDir);

        var keys =
            KeyStore.CreateAndSave(
                username,
                password,
                path);

        var resp =
            await RequestAsync<
                RegisterRequest,
                RegisterResponse>(
                    PacketType.RegisterRequest,

                    new RegisterRequest
                    {
                        Username = username,
                        Password = password,

                        // ElGamal Public Key
                        PublicKeyB64 =
        BigIntUtil.ToB64(
            keys.PublicKeyY),

                        // RSA Public Key
                        RsaPublicKeyB64 =
        keys.Rsa is null
            ? ""
            : Convert.ToBase64String(
                keys.Rsa.PublicKey)
                    },

                    PacketType.RegisterResponse);

        if (resp.Success)
        {
            Username = username;
            MyKeys = keys;
        }

        return (
            resp.Success,
            resp.Message);
    }

    // =========================================================
    // LOGIN
    // =========================================================

    public async Task<(bool ok, string message)> LoginAsync(
        string username,
        string password,
        string keyDir)
    {
        var path =
            KeyStore.DefaultPath(
                username,
                keyDir);

        if (!KeyStore.Exists(path))
        {
            return (
                false,
                "Không tìm thấy khóa cục bộ cho người dùng này.");
        }

        ElGamalKeyPair keys;

        try
        {
            keys = KeyStore.Load(
                password,
                path);
        }
        catch (Exception ex)
        {
            return (
                false,
                ex.Message);
        }

        var resp =
            await RequestAsync<
                LoginRequest,
                LoginResponse>(
                    PacketType.LoginRequest,

                    new LoginRequest
                    {
                        Username = username,
                        Password = password
                    },

                    PacketType.LoginResponse);

        if (resp.Success)
        {
            Username = username;
            MyKeys = keys;
        }

        return (
            resp.Success,
            resp.Message);
    }

    // =========================================================
    // LIST USERS
    // =========================================================

    public async Task<List<UserSummary>> ListUsersAsync()
    {
        var resp =
            await RequestAsync<
                ListUsersRequest,
                ListUsersResponse>(
                    PacketType.ListUsersRequest,
                    new ListUsersRequest(),
                    PacketType.ListUsersResponse);

        return resp.Users;
    }

    // =========================================================
    // GET PUBLIC KEY
    // =========================================================

    private async Task<BigInteger> GetPeerPublicKeyAsync(
        string username)
    {
        if (_peerKeyCache.TryGetValue(
            username,
            out var cached))
        {
            return cached;
        }

        var resp =
            await RequestAsync<
                PublicKeyRequest,
                PublicKeyResponse>(
                    PacketType.PublicKeyRequest,

                    new PublicKeyRequest
                    {
                        Username = username
                    },

                    PacketType.PublicKeyResponse);

        if (!resp.Found)
        {
            throw new InvalidOperationException(
                $"Không tìm thấy người dùng '{username}'.");
        }

        var key =
            BigIntUtil.FromB64(
                resp.PublicKeyB64);

        _peerKeyCache[username] = key;

        return key;
    }
    private async Task<byte[]> GetPeerRsaPublicKeyAsync(
    string username)
    {
        if (_peerRsaKeyCache.TryGetValue(
            username,
            out var cached))
        {
            return cached;
        }

        var resp =
            await RequestAsync<
                PublicKeyRequest,
                PublicKeyResponse>(
                    PacketType.PublicKeyRequest,

                    new PublicKeyRequest
                    {
                        Username = username
                    },

                    PacketType.PublicKeyResponse);

        if (!resp.Found)
        {
            throw new InvalidOperationException(
                $"Không tìm thấy người dùng '{username}'.");
        }

        if (string.IsNullOrWhiteSpace(
            resp.RsaPublicKeyB64))
        {
            throw new InvalidOperationException(
                $"Người dùng '{username}' chưa có RSA Public Key.");
        }

        var key =
            Convert.FromBase64String(
                resp.RsaPublicKeyB64);

        _peerRsaKeyCache[username] = key;

        return key;
    }

    // =========================================================
    // SEND CHAT
    // =========================================================

    public async Task<CryptoMetrics> SendChatAsync(
        string toUsername,
        string plaintext)
    {
        if (Username == null || MyKeys == null)
        {
            throw new InvalidOperationException(
                "Chưa đăng nhập.");
        }

        if (string.IsNullOrWhiteSpace(toUsername))
        {
            throw new ArgumentException(
                "Tên người nhận không được để trống.");
        }

        if (string.IsNullOrEmpty(plaintext))
        {
            throw new ArgumentException(
                "Nội dung tin nhắn không được để trống.");
        }

        // Lấy public key người nhận
        var peerKey =
     await GetPeerPublicKeyAsync(
         toUsername);

        var peerRsaKey =
            await GetPeerRsaPublicKeyAsync(
                toUsername);

        // Mã hóa
        var envelope =
            HybridEncryption.Encrypt(
                Username,
                MyKeys,
                toUsername,
                peerKey,
                peerRsaKey,
                plaintext);

        // Gửi server
        await SendAsync(
            PacketType.ChatSend,

            new ChatSendRequest
            {
                Envelope =
                    EnvelopeDto.From(envelope)
            });

        return envelope.Metrics!;
    }
    // =========================================================
    // HANDLE INCOMING MESSAGE
    // =========================================================

    private async Task HandleIncomingAsync(
    EnvelopeDto dto)
    {
        if (MyKeys == null)
            return;

        try
        {
            // Lấy public key người gửi
            var senderKey =
                await GetPeerPublicKeyAsync(
                    dto.SenderId);

            // Chuyển DTO thành envelope
            var envelope =
                dto.ToEnvelope();

            // Giải mã
            var decrypted =
                HybridEncryption.Decrypt(
                    envelope,
                    MyKeys,
                    senderKey);

            // Phát sự kiện cho giao diện
            OnIncomingMessage?.Invoke(
                new IncomingChatEvent(
                    dto.SenderId,
                    decrypted,
                    envelope.Timestamp));
        }
        catch (Exception ex)
        {
            OnServerError?.Invoke(
                $"Không thể giải mã tin nhắn từ " +
                $"{dto.SenderId}: {ex.Message}");
        }
    }

    // =========================================================
    // LOAD HISTORY
    // =========================================================

    public async Task<
        List<(
            string sender,
            DecryptedMessage msg,
            DateTimeOffset ts)>>
        LoadHistoryAsync(
            string withUsername)
    {
        if (MyKeys == null)
        {
            throw new InvalidOperationException(
                "Chưa đăng nhập.");
        }

        var resp =
            await RequestAsync<
                HistoryRequest,
                HistoryResponse>(
                    PacketType.HistoryRequest,

                    new HistoryRequest
                    {
                        WithUsername =
                            withUsername
                    },

                    PacketType.HistoryResponse);

        var result =
            new List<(
                string sender,
                DecryptedMessage msg,
                DateTimeOffset ts)>();

        foreach (var dto in resp.Envelopes)
        {
            try
            {
                var otherParty =
                    dto.SenderId == Username
                        ? dto.ReceiverId
                        : dto.SenderId;

                var otherKey =
                    await GetPeerPublicKeyAsync(
                        otherParty);

                var envelope =
                    dto.ToEnvelope();

                var decrypted =
                    HybridEncryption.Decrypt(
                        envelope,
                        MyKeys,
                        otherKey);

                result.Add(
                    (
                        dto.SenderId,
                        decrypted,
                        envelope.Timestamp
                    ));
            }
            catch (Exception ex)
            {
                OnServerError?.Invoke(
                    "Bỏ qua một tin nhắn lịch sử " +
                    $"không giải mã được: {ex.Message}");
            }
        }

        return result;
    }

    // =========================================================
    // DISPOSE
    // =========================================================

    public async ValueTask DisposeAsync()
    {
        _readLoopCts?.Cancel();

        _incomingQueue.Writer.TryComplete();

        _stream?.Close();

        _tcp.Close();

        await Task.CompletedTask;
    }
}

// Request dùng cho ListUsers
public sealed class ListUsersRequest
{
}