using System.Text;
using System.Text.Json;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.Services;

public class ChatMessage
{
    public string Sender { get; set; } = "";
    public string Receiver { get; set; } = "";
    public string Content { get; set; } = "";
    public DateTime SentAt { get; set; }
}

public class MessageStore
{
    private readonly string _path;
    private readonly object _lock = new();

    private readonly byte[] _encryptionKey;

    public MessageStore(string path)
    {
        _path = path;

        // Tạo file chứa khóa AES nếu chưa có
        var keyPath = Path.Combine(
            Path.GetDirectoryName(
                Path.GetFullPath(_path)
            )!,
            "encryption.key"
        );

        if (File.Exists(keyPath))
        {
            _encryptionKey = File.ReadAllBytes(keyPath);
        }
        else
        {
            _encryptionKey = AesGcmCipher.GenerateKey();

            File.WriteAllBytes(
                keyPath,
                _encryptionKey
            );
        }
    }

    private List<ChatMessage> Load()
    {
        if (!File.Exists(_path))
            return new List<ChatMessage>();

        var json = File.ReadAllText(_path);

        if (string.IsNullOrWhiteSpace(json))
            return new List<ChatMessage>();

        return JsonSerializer.Deserialize<List<ChatMessage>>(json)
               ?? new List<ChatMessage>();
    }

    private void Save(List<ChatMessage> messages)
    {
        var directory = Path.GetDirectoryName(
            Path.GetFullPath(_path)
        );

        if (directory != null)
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(
            messages,
            new JsonSerializerOptions
            {
                WriteIndented = true
            }
        );

        File.WriteAllText(_path, json);
    }

    public void Add(
        string sender,
        string receiver,
        string content)
    {
        lock (_lock)
        {
            var messages = Load();

            // Chuyển nội dung sang byte
            var plaintext =
                Encoding.UTF8.GetBytes(content);

            // Mã hóa AES-256-GCM
            var encrypted =
                AesGcmCipher.Encrypt(
                    _encryptionKey,
                    plaintext
                );

            // Chuyển ciphertext thành Base64 để lưu JSON
            var encryptedContent =
                Convert.ToBase64String(encrypted);

            messages.Add(new ChatMessage
            {
                Sender = sender,
                Receiver = receiver,

                // LƯU NỘI DUNG ĐÃ MÃ HÓA
                Content = encryptedContent,

                SentAt = DateTime.Now
            });

            Save(messages);
        }
    }

    public List<ChatMessage> GetConversation(
        string user1,
        string user2)
    {
        lock (_lock)
        {
            var messages = Load();

            var conversation = messages
                .Where(m =>
                    (m.Sender.Equals(
                        user1,
                        StringComparison.OrdinalIgnoreCase)
                     &&
                     m.Receiver.Equals(
                        user2,
                        StringComparison.OrdinalIgnoreCase))
                    ||
                    (m.Sender.Equals(
                        user2,
                        StringComparison.OrdinalIgnoreCase)
                     &&
                     m.Receiver.Equals(
                        user1,
                        StringComparison.OrdinalIgnoreCase))
                )
                .OrderBy(m => m.SentAt)
                .ToList();

            // Giải mã nội dung trước khi trả về giao diện
            foreach (var message in conversation)
            {
                try
                {
                    var encrypted =
                        Convert.FromBase64String(
                            message.Content
                        );

                    var plaintext =
                        AesGcmCipher.Decrypt(
                            _encryptionKey,
                            encrypted
                        );

                    message.Content =
                        Encoding.UTF8.GetString(
                            plaintext
                        );
                }
                catch
                {
                    // Tin nhắn cũ chưa được mã hóa
                    // hoặc dữ liệu không hợp lệ
                    message.Content =
                        "[Không thể giải mã tin nhắn]";
                }
            }

            return conversation;
        }
    }
}