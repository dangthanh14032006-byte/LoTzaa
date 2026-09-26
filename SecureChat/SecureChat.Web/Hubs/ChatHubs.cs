using System.Numerics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using SecureChat.Core.Crypto;
using SecureChat.Core.Services;
using SecureChat.Web.Services;
namespace SecureChat.Web.Hubs;

[Authorize]
public class ChatHub : Hub
{
    private readonly UserStore _users;
    private readonly KeySessionCache _keyCache;
    private readonly EncryptedMessageStore _messages;
    private readonly GroupStore _groups;
    private readonly GroupMessageStore _groupMessages;
    private readonly FriendStore _friendStore;
    private readonly UserPresenceService _presence;
    public ChatHub(
        UserStore users, KeySessionCache keyCache, EncryptedMessageStore messages,
        GroupStore groups, GroupMessageStore groupMessages, FriendStore friendStore, UserPresenceService presence)
    {
        _users = users;
        _keyCache = keyCache;
        _messages = messages;
        _groups = groups;
        _groupMessages = groupMessages;
        _friendStore = friendStore;
        _presence = presence;
    }
    public List<string> GetOnlineUsers()
    {
        return _presence.GetOnlineUsers();
    }

    public override async Task OnConnectedAsync()
    {
        var username = Context.User?.Identity?.Name;

        if (!string.IsNullOrWhiteSpace(username))
        {
            bool justCameOnline =
                _presence.UserConnected(username, Context.ConnectionId);

            if (justCameOnline)
                await Clients.Others.SendAsync("UserOnline", username);
        }

        await base.OnConnectedAsync();
                await Clients.Caller.SendAsync(
            "OnlineUsersSnapshot",
            _presence.GetOnlineUsers());
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var username = Context.User?.Identity?.Name;

        if (!string.IsNullOrWhiteSpace(username))
        {
            bool wentOffline =
                _presence.UserDisconnected(username, Context.ConnectionId);

            if (wentOffline)
                await Clients.Others.SendAsync("UserOffline", username);
        }

        await base.OnDisconnectedAsync(exception);
    }
    public async Task SendMessage(string receiver, string message)
    {
        try
        {
            Console.WriteLine("========== SEND MESSAGE ==========");
            Console.WriteLine($"Receiver: {receiver}");
            Console.WriteLine($"Message length: {message?.Length ?? 0}");

            if (string.IsNullOrWhiteSpace(message))
            {
                Console.WriteLine("[ChatHub] Tin nhắn rỗng.");
                throw new HubException("Tin nhắn không được để trống.");
            }

            var sender = Context.User?.Identity?.Name;

            Console.WriteLine($"Sender: {sender ?? "(null)"}");
            Console.WriteLine(
                $"Authenticated: {Context.User?.Identity?.IsAuthenticated}");

            if (string.IsNullOrWhiteSpace(sender))
            {
                throw new HubException(
                    "Không xác định được người gửi. Phiên đăng nhập SignalR không hợp lệ.");
            }

            // =====================================================
            // KIỂM TRA KEY CACHE
            // =====================================================

            if (!_keyCache.TryGet(sender, out var senderKeys))
            {
                Console.WriteLine(
                    $"[ChatHub] KHÔNG tìm thấy key cache cho: {sender}");

                throw new HubException(
                    $"Không tìm thấy khóa phiên của tài khoản '{sender}'. " +
                    "Hãy đăng xuất và đăng nhập lại.");
            }

            Console.WriteLine("[ChatHub] Sender keys: OK");

            // =====================================================
            // TÌM TÀI KHOẢN
            // =====================================================

            var receiverAccount = _users.Find(receiver);
            var senderAccount = _users.Find(sender);

            if (receiverAccount == null)
            {
                throw new HubException(
                    $"Không tìm thấy người nhận '{receiver}'.");
            }

            if (senderAccount == null)
            {
                throw new HubException(
                    $"Không tìm thấy tài khoản người gửi '{sender}'.");
            }
            if (!_friendStore.AreFriends(sender, receiver))
            {
                throw new HubException(
                    "Hai tài khoản cần chấp nhận lời mời kết bạn trước khi nhắn tin.");
            }
            Console.WriteLine("[ChatHub] Sender account: OK");
            Console.WriteLine("[ChatHub] Receiver account: OK");

            // =====================================================
            // ELGAMAL PUBLIC KEY
            // =====================================================

            if (string.IsNullOrWhiteSpace(receiverAccount.PublicKeyB64))
            {
                throw new HubException(
                    $"Người nhận '{receiver}' chưa có ElGamal Public Key.");
            }

            if (string.IsNullOrWhiteSpace(senderAccount.PublicKeyB64))
            {
                throw new HubException(
                    $"Người gửi '{sender}' chưa có ElGamal Public Key.");
            }

            var receiverPub =
                BigIntUtil.FromB64(receiverAccount.PublicKeyB64);

            var senderPub =
                BigIntUtil.FromB64(senderAccount.PublicKeyB64);

            Console.WriteLine("[ChatHub] ElGamal public keys: OK");

            // =====================================================
            // RSA PUBLIC KEY
            // =====================================================

            if (string.IsNullOrWhiteSpace(receiverAccount.RsaPublicKeyB64))
            {
                throw new HubException(
                    $"Người nhận '{receiver}' chưa có RSA Public Key.");
            }

            if (string.IsNullOrWhiteSpace(senderAccount.RsaPublicKeyB64))
            {
                throw new HubException(
                    $"Người gửi '{sender}' chưa có RSA Public Key.");
            }

            var receiverRsaPub =
                Convert.FromBase64String(
                    receiverAccount.RsaPublicKeyB64);

            var senderRsaPub =
                Convert.FromBase64String(
                    senderAccount.RsaPublicKeyB64);

            Console.WriteLine("[ChatHub] RSA public keys: OK");

            // =====================================================
            // MÃ HÓA CHO NGƯỜI NHẬN
            // =====================================================

            Console.WriteLine(
                "[ChatHub] Đang mã hóa message cho receiver...");

            var forReceiver =
                HybridEncryption.Encrypt(
                    sender,
                    senderKeys,
                    receiver,
                    receiverPub,
                    receiverRsaPub,
                    message);

            Console.WriteLine("[ChatHub] Encrypt receiver: OK");

            // =====================================================
            // MÃ HÓA BẢN COPY CHO NGƯỜI GỬI
            // =====================================================

            Console.WriteLine(
                "[ChatHub] Đang tạo bản copy cho sender...");

            var forSenderCopy =
                HybridEncryption.Encrypt(
                    sender,
                    senderKeys,
                    sender,
                    senderPub,
                    senderRsaPub,
                    message);

            Console.WriteLine("[ChatHub] Encrypt sender copy: OK");

            // =====================================================
            // LƯU
            // =====================================================

            _messages.Add(
                new StoredMessage
                {
                    ForReceiver = forReceiver,
                    ForSenderCopy = forSenderCopy
                });

            Console.WriteLine("[ChatHub] Message stored: OK");

            // =====================================================
            // GIẢI MÃ KIỂM TRA
            // =====================================================

            DecryptedMessage? decrypted = null;

            if (_keyCache.TryGet(receiver, out var receiverKeys))
            {
                Console.WriteLine(
                    "[ChatHub] Receiver đang online -> test decrypt...");

                decrypted =
                    HybridEncryption.Decrypt(
                        forReceiver,
                        receiverKeys,
                        senderPub);

                Console.WriteLine(
                    $"[ChatHub] Decrypt OK. " +
                    $"Signature={decrypted.SignatureValid}, " +
                    $"SHA={decrypted.Sha256Match}");
            }
            else
            {
                Console.WriteLine(
                    "[ChatHub] Receiver không có key cache/không online.");
            }

            // =====================================================
            // METRICS
            // =====================================================

            var metrics =
                new MessageMetricsDto
                {
                    EncryptMs =
                        forReceiver.Metrics?.EncryptMs ?? 0,

                    DecryptMs =
                        decrypted?.Metrics.DecryptMs,

                    PlaintextBytes =
                        forReceiver.Metrics?.PlaintextBytes ?? 0,

                    CiphertextBytes =
                        forReceiver.Metrics?.CiphertextBytes ?? 0,

                    Overhead =
                        forReceiver.Metrics?.Overhead ?? 0,

                    SignatureValid =
                        decrypted?.SignatureValid,

                    Sha256Match =
                        decrypted?.Sha256Match
                };

            // =====================================================
            // GỬI QUA SIGNALR
            // =====================================================

            Console.WriteLine(
                $"[ChatHub] Sending to user '{receiver}'...");

            await Clients.User(receiver)
                .SendAsync(
                    "ReceiveMessage",
                    sender,
                    message);

            Console.WriteLine(
                $"[ChatHub] Sending to sender '{sender}'...");

            await Clients.User(sender)
                .SendAsync(
                    "ReceiveMessage",
                    sender,
                    message);

            await Clients.User(sender)
                .SendAsync(
                    "ReceiveMetrics",
                    metrics);

            if (decrypted != null)
            {
                await Clients.User(receiver)
                    .SendAsync(
                        "ReceiveMetrics",
                        metrics);
            }

            Console.WriteLine(
                "[ChatHub] ===== SEND SUCCESS =====");
        }
        catch (HubException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                "[ChatHub] ===== SEND ERROR =====");

            Console.WriteLine(ex.ToString());

            throw new HubException(
                "Lỗi khi gửi tin nhắn: " + ex.Message);
        }
    }

    public async Task LoadHistory(string withUser)
    {
        var me = Context.User?.Identity?.Name;
        if (!_friendStore.AreFriends(me, withUser))
            return;
        if (string.IsNullOrWhiteSpace(me))
            throw new HubException("Không xác định được tài khoản đang đăng nhập.");

        if (!_keyCache.TryGet(me, out var myKeys))
            throw new HubException("Không tìm thấy khóa phiên. Hãy đăng xuất rồi đăng nhập lại.");
        
        var other = _users.Find(withUser);
        if (other == null)
            throw new HubException($"Không tìm thấy tài khoản '{withUser}'.");

        foreach (var stored in _messages.GetConversation(me, withUser))
        {
            try
            {
                // Nếu mình là người nhận, giải mã bản nhận.
                // Nếu mình là người gửi, giải mã bản sao dành cho người gửi.
                var isIncoming = stored.ForReceiver.ReceiverId.Equals(
                    me,
                    StringComparison.OrdinalIgnoreCase);

                var envelope = isIncoming
                    ? stored.ForReceiver
                    : stored.ForSenderCopy;

                // Dùng khóa công khai của đúng người gửi tin này để kiểm tra chữ ký.
                var envelopeSender = _users.Find(envelope.SenderId);
                if (envelopeSender == null ||
                    string.IsNullOrWhiteSpace(envelopeSender.PublicKeyB64))
                {
                    Console.WriteLine(
                        $"Bỏ qua tin nhắn vì thiếu khóa người gửi: {envelope.SenderId}");
                    continue;
                }

                var senderPublicKey = BigIntUtil.FromB64(envelopeSender.PublicKeyB64);
                var decrypted = HybridEncryption.Decrypt(
                    envelope,
                    myKeys,
                    senderPublicKey);

                await Clients.Caller.SendAsync(
                    "ReceiveMessage",
                    envelope.SenderId,
                    decrypted.PlaintextUtf8);

                await Clients.Caller.SendAsync(
                    "ReceiveMetrics",
                    new MessageMetricsDto
                    {
                        EncryptMs = envelope.Metrics?.EncryptMs ?? 0,
                        DecryptMs = decrypted.Metrics.DecryptMs,
                        PlaintextBytes = decrypted.Metrics.PlaintextBytes,
                        CiphertextBytes = decrypted.Metrics.CiphertextBytes,
                        Overhead = decrypted.Metrics.Overhead,
                        SignatureValid = decrypted.SignatureValid,
                        Sha256Match = decrypted.Sha256Match
                    });
            }
            catch (Exception ex)
            {
                // Một tin cũ bị lỗi không làm mất các tin còn lại.
                Console.WriteLine(
                    $"Không giải mã được một tin trong lịch sử chat: {ex}");
            }
        }
    }

    public async Task SendGroupMessage(string groupId, string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return;
        var sender = Context.User?.Identity?.Name;
        if (string.IsNullOrWhiteSpace(sender)) return;
        if (!_keyCache.TryGet(sender, out var senderKeys)) return;

        var group = _groups.Find(groupId);
        if (group == null || !group.Members.Any(m => m.Equals(sender, StringComparison.OrdinalIgnoreCase))) return;

        var memberPublicKeys = new Dictionary<string, BigInteger>(StringComparer.OrdinalIgnoreCase);
        foreach (var member in group.Members)
        {
            var acc = _users.Find(member);
            if (acc != null) memberPublicKeys[member] = BigIntUtil.FromB64(acc.PublicKeyB64);
        }

        var envelope = GroupEncryption.Encrypt(groupId, sender, senderKeys, memberPublicKeys, message);
        _groupMessages.Add(envelope);

        foreach (var member in group.Members)
            await Clients.User(member).SendAsync("ReceiveGroupMessage", groupId, sender, message);
    }

    public async Task LoadGroupHistory(string groupId)
    {
        var me = Context.User?.Identity?.Name;
        if (string.IsNullOrWhiteSpace(me)) return;
        if (!_keyCache.TryGet(me, out var myKeys)) return;

        var group = _groups.Find(groupId);
        if (group == null || !group.Members.Any(m => m.Equals(me, StringComparison.OrdinalIgnoreCase))) return;

        foreach (var envelope in _groupMessages.GetForGroup(groupId))
        {
            var senderAcc = _users.Find(envelope.SenderId);
            if (senderAcc == null) continue;
            var senderPub = BigIntUtil.FromB64(senderAcc.PublicKeyB64);

            try
            {
                var (plaintext, sigValid, shaMatch) = GroupEncryption.Decrypt(envelope, me, myKeys, senderPub);
                await Clients.Caller.SendAsync("ReceiveGroupMessage", groupId, envelope.SenderId, plaintext);
            }
            catch
            {
                // Bỏ qua tin nhắn không giải mã được (ví dụ gửi trước khi mình vào nhóm)
            }
        }
    }
    public async Task LoadConversationSummaries()
    {
        var me = Context.User?.Identity?.Name;

        if (string.IsNullOrWhiteSpace(me))
            return;

        if (!_keyCache.TryGet(me, out var myKeys))
            return;

        // Tóm tắt các cuộc trò chuyện riêng
        foreach (var username in _users.AllUsernames())
        {
            if (username.Equals(me, StringComparison.OrdinalIgnoreCase))
                continue;

            var other = _users.Find(username);
            var latest = _messages.GetConversation(me, username).LastOrDefault();

            if (other == null || latest == null)
                continue;

            var envelope = latest.ForReceiver.ReceiverId.Equals(
                me, StringComparison.OrdinalIgnoreCase)
                    ? latest.ForReceiver
                    : latest.ForSenderCopy;

            try
            {
                var decrypted = HybridEncryption.Decrypt(
                    envelope,
                    myKeys,
                    BigIntUtil.FromB64(other.PublicKeyB64));

                await Clients.Caller.SendAsync(
                    "ConversationSummary",
                    "user",
                    username,
                    decrypted.PlaintextUtf8,
                    envelope.Timestamp);
            }
            catch
            {
                // Bỏ qua tin nhắn không giải mã được.
            }
        }

        // Tóm tắt các nhóm
        foreach (var group in _groups.ForUser(me))
        {
            var latest = _groupMessages.GetForGroup(group.Id).LastOrDefault();

            if (latest == null)
                continue;

            var sender = _users.Find(latest.SenderId);

            if (sender == null)
                continue;

            try
            {
                var decrypted = GroupEncryption.Decrypt(
                    latest,
                    me,
                    myKeys,
                    BigIntUtil.FromB64(sender.PublicKeyB64));

                await Clients.Caller.SendAsync(
                    "ConversationSummary",
                    "group",
                    group.Id,
                    decrypted.plaintext,
                    latest.Timestamp);
            }
            catch
            {
                // Bỏ qua tin nhắn không giải mã được.
            }
        }
    }
}
public sealed class MessageMetricsDto
{
    public double EncryptMs { get; init; }
    public double? DecryptMs { get; init; }
    public int PlaintextBytes { get; init; }
    public int CiphertextBytes { get; init; }
    public double Overhead { get; init; }
    public bool? SignatureValid { get; init; }
    public bool? Sha256Match { get; init; }
}
