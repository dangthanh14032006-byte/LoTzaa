using System.Net;
using System.Net.Sockets;
using SecureChat.Core.Protocol;
using SecureChat.Core.Services;

namespace SecureChat.Server;

/// <summary>
/// Server chat: KHÔNG bao giờ nhìn thấy nội dung tin nhắn ở dạng rõ.
/// </summary>
public sealed class ChatServer
{
    private readonly UserStore _users;
    private readonly ChatHistoryStore _history;
    private readonly int _port;

    private readonly Dictionary<string, ClientSession> _online =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly object _onlineLock = new();

    public ChatServer(int port, string dataDir)
    {
        _port = port;

        _users = new UserStore(
            Path.Combine(dataDir, "users.json")
        );

        _history = new ChatHistoryStore(
            Path.Combine(dataDir, "history")
        );
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var listener =
            new TcpListener(IPAddress.Any, _port);

        listener.Start();

        Console.WriteLine(
            $"[Server] Đang lắng nghe tại cổng {_port}..."
        );

        while (!ct.IsCancellationRequested)
        {
            TcpClient tcp;

            try
            {
                tcp =
                    await listener.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            _ = HandleClientAsync(tcp, ct);
        }
    }

    private async Task HandleClientAsync(
        TcpClient tcp,
        CancellationToken ct)
    {
        var session = new ClientSession(tcp);

        string? loggedInAs = null;

        try
        {
            var stream = tcp.GetStream();

            var buffer = new StreamReadBuffer();

            while (true)
            {
                var packet =
                    await WireCodec.ReadPacketAsync(
                        stream,
                        buffer,
                        ct
                    );

                if (packet == null)
                    break;

                switch (packet.Type)
                {
                    // =====================================================
                    // ĐĂNG KÝ
                    // =====================================================
                    case PacketType.RegisterRequest:
                        {
                            var req =
                                WireCodec.ReadPayload<RegisterRequest>(
                                    packet
                                );

                            bool ok =
                                _users.TryRegister(
                                    req.Username,
                                    req.Password,
                                    "", // console TCP server chưa hỗ trợ đăng ký bằng SĐT
                                    req.PublicKeyB64,
                                    out var err,
                                    req.RsaPublicKeyB64
                                );

                            await SendAsync(
                                stream,
                                PacketType.RegisterResponse,
                                new RegisterResponse
                                {
                                    Success = ok,
                                    Message = ok
                                        ? "Đăng ký thành công."
                                        : err
                                },
                                ct
                            );

                            break;
                        }

                    // =====================================================
                    // ĐĂNG NHẬP
                    // =====================================================
                    case PacketType.LoginRequest:
                        {
                            var req =
                                WireCodec.ReadPayload<LoginRequest>(
                                    packet
                                );

                            bool ok =
                                _users.TryLogin(
                                    req.Username,
                                    req.Password,
                                    out var err
                                );

                            if (ok)
                            {
                                lock (_onlineLock)
                                {
                                    _online[req.Username] =
                                        session;
                                }

                                loggedInAs =
                                    req.Username;
                            }

                            await SendAsync(
                                stream,
                                PacketType.LoginResponse,
                                new LoginResponse
                                {
                                    Success = ok,
                                    Message = ok
                                        ? "Đăng nhập thành công."
                                        : err
                                },
                                ct
                            );

                            break;
                        }

                    // =====================================================
                    // DANH SÁCH USER
                    // =====================================================
                    case PacketType.ListUsersRequest:
                        {
                            List<string> onlineNames;

                            lock (_onlineLock)
                            {
                                onlineNames =
                                    _online.Keys.ToList();
                            }

                            var resp =
                                new ListUsersResponse
                                {
                                    Users =
                                        _users
                                            .AllUsernames()
                                            .Select(
                                                u =>
                                                    new UserSummary
                                                    {
                                                        Username = u,
                                                        Online =
                                                            onlineNames.Contains(u)
                                                    }
                                            )
                                            .ToList()
                                };

                            await SendAsync(
                                stream,
                                PacketType.ListUsersResponse,
                                resp,
                                ct
                            );

                            break;
                        }

                    // =====================================================
                    // LẤY PUBLIC KEY
                    // =====================================================
                    case PacketType.PublicKeyRequest:
                        {
                            var req =
                                WireCodec.ReadPayload<PublicKeyRequest>(
                                    packet
                                );

                            var acc =
                                _users.Find(req.Username);

                            await SendAsync(
                                stream,
                                PacketType.PublicKeyResponse,
                                new PublicKeyResponse
                                {
                                    Found = acc != null,

                                    Username =
                                        req.Username,

                                    // ElGamal public key
                                    PublicKeyB64 =
                                        acc?.PublicKeyB64 ?? "",

                                    // RSA public key
                                    RsaPublicKeyB64 =
                                        acc?.RsaPublicKeyB64 ?? ""
                                },
                                ct
                            );

                            break;
                        }

                    // =====================================================
                    // GỬI TIN NHẮN
                    // =====================================================
                    case PacketType.ChatSend:
                        {
                            var req =
                                WireCodec.ReadPayload<ChatSendRequest>(
                                    packet
                                );

                            _history.Append(
                                req.Envelope
                            );

                            ClientSession? target;

                            lock (_onlineLock)
                            {
                                _online.TryGetValue(
                                    req.Envelope.ReceiverId,
                                    out target
                                );
                            }

                            if (target != null)
                            {
                                try
                                {
                                    await SendAsync(
                                        target.Stream,
                                        PacketType.ChatIncoming,
                                        new ChatIncoming
                                        {
                                            Envelope =
                                                req.Envelope
                                        },
                                        ct
                                    );
                                }
                                catch
                                {
                                    // Người nhận vừa ngắt kết nối.
                                    // Tin nhắn vẫn đã được lưu.
                                }
                            }

                            break;
                        }

                    // =====================================================
                    // LỊCH SỬ
                    // =====================================================
                    case PacketType.HistoryRequest:
                        {
                            if (loggedInAs == null)
                                break;

                            var req =
                                WireCodec.ReadPayload<HistoryRequest>(
                                    packet
                                );

                            var list =
                                _history.Get(
                                    loggedInAs,
                                    req.WithUsername
                                );

                            await SendAsync(
                                stream,
                                PacketType.HistoryResponse,
                                new HistoryResponse
                                {
                                    Envelopes = list
                                },
                                ct
                            );

                            break;
                        }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"[Server] Lỗi phiên " +
                $"{loggedInAs ?? "(chưa đăng nhập)"}: " +
                $"{ex.Message}"
            );
        }
        finally
        {
            if (loggedInAs != null)
            {
                lock (_onlineLock)
                {
                    _online.Remove(loggedInAs);
                }
            }

            tcp.Close();
        }
    }

    private static Task SendAsync<T>(
        NetworkStream stream,
        PacketType type,
        T payload,
        CancellationToken ct
    ) =>
        WireCodec.WritePacketAsync(
            stream,
            WireCodec.MakePacket(
                type,
                payload
            ),
            ct
        );

    private sealed class ClientSession
    {
        public TcpClient Tcp { get; }

        public NetworkStream Stream { get; }

        public ClientSession(TcpClient tcp)
        {
            Tcp = tcp;
            Stream = tcp.GetStream();
        }
    }
}