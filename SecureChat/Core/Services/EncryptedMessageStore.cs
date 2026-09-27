using System.Text.Json;
using SecureChat.Core.Crypto;

namespace SecureChat.Web.Services;

public sealed class StoredMessage
{
    public required EncryptedEnvelope ForReceiver { get; init; }
    public required EncryptedEnvelope ForSenderCopy { get; init; }
}

public sealed class EncryptedMessageStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly List<StoredMessage> _cache;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public EncryptedMessageStore(string path)
    {
        _path = path;
        _cache = LoadFromDisk();
    }

    private List<StoredMessage> LoadFromDisk()
    {
        if (!File.Exists(_path))
            return new();

        var json = File.ReadAllText(_path);

        if (string.IsNullOrWhiteSpace(json))
            return new();

        try
        {
            return JsonSerializer.Deserialize<List<StoredMessage>>(
                json,
                JsonOptions
            ) ?? new();
        }
        catch (JsonException ex)
        {
            Console.WriteLine(
                $"[EncryptedMessageStore] Không thể đọc lịch sử tin nhắn: {ex.Message}"
            );

            return new();
        }
    }

    private void Persist(List<StoredMessage> list)
    {
        var directory =
            Path.GetDirectoryName(
                Path.GetFullPath(_path)
            );

        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        File.WriteAllText(
            _path,
            JsonSerializer.Serialize(
                list,
                JsonOptions
            )
        );
    }

    public void Add(StoredMessage msg)
    {
        lock (_lock)
        {
            _cache.Add(msg);
            Persist(_cache);
        }
    }

    public List<StoredMessage> GetConversation(
        string user1,
        string user2)
    {
        lock (_lock)
        {
            return _cache
                .Where(m =>
                    (
                        m.ForReceiver.SenderId.Equals(
                            user1,
                            StringComparison.OrdinalIgnoreCase)
                        &&
                        m.ForReceiver.ReceiverId.Equals(
                            user2,
                            StringComparison.OrdinalIgnoreCase)
                    )
                    ||
                    (
                        m.ForReceiver.SenderId.Equals(
                            user2,
                            StringComparison.OrdinalIgnoreCase)
                        &&
                        m.ForReceiver.ReceiverId.Equals(
                            user1,
                            StringComparison.OrdinalIgnoreCase)
                    )
                )
                .OrderBy(m => m.ForReceiver.Timestamp)
                .ToList();
        }
    }
}