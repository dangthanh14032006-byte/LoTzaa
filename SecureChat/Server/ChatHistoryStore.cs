using System.Text.Json;
using SecureChat.Core.Protocol;

namespace SecureChat.Server;

/// <summary>
/// Lưu lịch sử tin nhắn theo cặp người dùng, mỗi cặp một file JSON chứa danh sách EnvelopeDto.
/// Server chỉ lưu trữ dữ liệu ĐÃ MÃ HÓA (mã hóa đầu-cuối) - không có khả năng đọc nội dung.
/// </summary>
public sealed class ChatHistoryStore
{
    private readonly string _dir;
    private readonly object _lock = new();

    public ChatHistoryStore(string dir)
    {
        _dir = dir;
        Directory.CreateDirectory(_dir);
    }

    private static string PairKey(string a, string b)
    {
        var ordered = new[] { a, b }.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToArray();
        return $"{ordered[0]}__{ordered[1]}".Replace(Path.DirectorySeparatorChar, '_');
    }

    private string PathFor(string a, string b) => Path.Combine(_dir, PairKey(a, b) + ".json");

    public void Append(EnvelopeDto envelope)
    {
        lock (_lock)
        {
            var path = PathFor(envelope.SenderId, envelope.ReceiverId);
            var list = File.Exists(path)
                ? JsonSerializer.Deserialize<List<EnvelopeDto>>(File.ReadAllText(path)) ?? new()
                : new List<EnvelopeDto>();
            list.Add(envelope);
            File.WriteAllText(path, JsonSerializer.Serialize(list));
        }
    }

    public List<EnvelopeDto> Get(string a, string b)
    {
        lock (_lock)
        {
            var path = PathFor(a, b);
            if (!File.Exists(path)) return new();
            return JsonSerializer.Deserialize<List<EnvelopeDto>>(File.ReadAllText(path)) ?? new();
        }
    }
}
