using SecureChat.Client;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine("=== SecureChat Client ===");
Console.WriteLine("Mã hóa: AES-256-GCM (nội dung) + ElGamal 2048-bit (trao khóa & chữ ký số) + SHA-256/MD5 (toàn vẹn)");

Console.Write("Địa chỉ server [127.0.0.1]: ");
var host = ReadLineOrDefault("127.0.0.1");
Console.Write("Cổng [5050]: ");
var portStr = ReadLineOrDefault("5050");
int port = int.TryParse(portStr, out var pp) ? pp : 5050;

string keyDir = Path.Combine(AppContext.BaseDirectory, "client-keys");
Directory.CreateDirectory(keyDir);

await using var client = new ChatClient();
client.OnIncomingMessage += e =>
{
    Console.WriteLine();
    Console.ForegroundColor = e.Message.FullyTrusted ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine($"[{e.Timestamp.ToLocalTime():HH:mm:ss}] {e.FromUsername}: {e.Message.PlaintextUtf8}");
    Console.ResetColor();
    Console.WriteLine($"   chữ ký hợp lệ={e.Message.SignatureValid}, SHA-256 khớp={e.Message.Sha256Match}, MD5 khớp={e.Message.Md5Match}");
    Console.WriteLine($"   {e.Message.Metrics}");
    Console.Write("> ");
};
client.OnServerError += msg =>
{
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[Cảnh báo] {msg}");
    Console.ResetColor();
    Console.Write("> ");
};

try
{
    await client.ConnectAsync(host, port);
    Console.WriteLine($"Đã kết nối tới {host}:{port}.");
}
catch (Exception ex)
{
    Console.WriteLine($"Không thể kết nối: {ex.Message}");
    return;
}

// --- Đăng ký / đăng nhập ---
while (client.Username == null)
{
    Console.WriteLine();
    Console.WriteLine("1) Đăng ký    2) Đăng nhập    3) Thoát");
    Console.Write("Chọn: ");
    var choice = Console.ReadLine();

    if (choice == "3") return;

    Console.Write("Tên đăng nhập: ");
    var username = Console.ReadLine() ?? "";
    Console.Write("Mật khẩu: ");
    var password = ReadPasswordMasked();

    if (choice == "1")
    {
        var (ok, msg) = await client.RegisterAsync(username, password, keyDir);
        Console.WriteLine(msg);
        if (ok) Console.WriteLine($"Đã sinh cặp khóa ElGamal 2048-bit và lưu (mã hóa) tại: {KeyPathFor(username, keyDir)}");
    }
    else if (choice == "2")
    {
        var (ok, msg) = await client.LoginAsync(username, password, keyDir);
        Console.WriteLine(msg);
    }
}

Console.WriteLine($"\nXin chào, {client.Username}! Gõ /help để xem lệnh.");

while (true)
{
    Console.Write("> ");
    var line = Console.ReadLine();
    if (line == null) break;
    line = line.Trim();
    if (line.Length == 0) continue;

    if (line == "/help")
    {
        Console.WriteLine("/users            - liệt kê người dùng (online/offline)");
        Console.WriteLine("/history <user>   - tải và giải mã lịch sử hội thoại với <user>");
        Console.WriteLine("/msg <user> <nd>  - gửi tin nhắn đã mã hóa tới <user>");
        Console.WriteLine("/benchmark        - đánh giá thời gian mã hóa/giải mã & kích thước dữ liệu (offline, không cần mạng)");
        Console.WriteLine("/quit             - thoát");
    }
    else if (line == "/benchmark")
    {
        RunBenchmark();
    }
    else if (line == "/users")
    {
        var users = await client.ListUsersAsync();
        foreach (var u in users)
            Console.WriteLine($"  {u.Username}  [{(u.Online ? "online" : "offline")}]");
    }
    else if (line.StartsWith("/history "))
    {
        var who = line["/history ".Length..].Trim();
        var hist = await client.LoadHistoryAsync(who);
        foreach (var (sender, msg, ts) in hist)
            Console.WriteLine($"[{ts.ToLocalTime():g}] {sender}: {msg.PlaintextUtf8}  (tin cậy={msg.FullyTrusted})");
        Console.WriteLine($"({hist.Count} tin nhắn)");
    }
    else if (line.StartsWith("/msg "))
    {
        var rest = line["/msg ".Length..];
        int sp = rest.IndexOf(' ');
        if (sp < 0) { Console.WriteLine("Cú pháp: /msg <user> <nội dung>"); continue; }
        var to = rest[..sp];
        var content = rest[(sp + 1)..];
        try
        {
            var metrics = await client.SendChatAsync(to, content);
            Console.WriteLine($"Đã gửi. {metrics}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi khi gửi: {ex.Message}");
        }
    }
    else if (line == "/quit")
    {
        break;
    }
    else
    {
        Console.WriteLine("Lệnh không hợp lệ. Gõ /help.");
    }
}

// Mục 9 & 10: đánh giá thời gian mã hóa/giải mã và kích thước dữ liệu sau mã hóa,
// chạy hoàn toàn cục bộ (không cần server) trên nhiều cỡ tin nhắn khác nhau.
void RunBenchmark()
{
    var self = SecureChat.Core.Crypto.ElGamal.GenerateKeyPair();
    var other = SecureChat.Core.Crypto.ElGamal.GenerateKeyPair();
    int[] sizes = { 16, 256, 1024, 4096, 16384, 65536 };

    Console.WriteLine();
    Console.WriteLine("Kích thước gốc | Mã hóa (ms) | Giải mã (ms) | Kích thước mã hóa | Hệ số phình");
    Console.WriteLine("----------------|-------------|--------------|--------------------|------------");

    foreach (var size in sizes)
    {
        // Dùng chuỗi ASCII cùng độ dài để mô phỏng tin nhắn chat thực (UTF-8 1 byte/ký tự cho ASCII).
        var text = new string('A', size);

        byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(text);
        var envelope = SecureChat.Core.Crypto.HybridEncryption.Encrypt("alice", self, "bob", other.PublicKeyY, textBytes, "");
        var decrypted = SecureChat.Core.Crypto.HybridEncryption.Decrypt(envelope, other, self.PublicKeyY);

        var m = envelope.Metrics!;
        Console.WriteLine($"{size,15} | {m.EncryptMs,11:F3} | {decrypted.Metrics.DecryptMs,12:F3} | " +
                           $"{m.CiphertextBytes,18} | {m.Overhead,10:F2}x");
    }

    Console.WriteLine();
    Console.WriteLine("Ghi chú: mỗi gói tin có chi phí cố định ~1104 byte (khóa AES bọc ElGamal 512B +");
    Console.WriteLine("chữ ký số ElGamal 512B + SHA-256 32B + MD5 16B + nonce/tag AES-GCM 28B), nên hệ số");
    Console.WriteLine("phình rất cao với tin nhắn ngắn và tiệm cận 1x khi tin nhắn dài (AES-GCM gần như không phình).");
}

static string ReadLineOrDefault(string def)
{
    var s = Console.ReadLine();
    return string.IsNullOrWhiteSpace(s) ? def : s.Trim();
}

static string KeyPathFor(string username, string keyDir) =>
    Path.Combine(keyDir, $"{username}.key.json");

static string ReadPasswordMasked()
{
    var pwd = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
        if (key.Key == ConsoleKey.Backspace)
        {
            if (pwd.Length > 0) { pwd.Length--; Console.Write("\b \b"); }
            continue;
        }
        if (!char.IsControl(key.KeyChar))
        {
            pwd.Append(key.KeyChar);
            Console.Write('*');
        }
    }
    return pwd.ToString();
}
