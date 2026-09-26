using System.Text;
using System.Text.Json;

namespace SecureChat.Core.Protocol;

/// <summary>
/// Đóng gói/mở gói Packet dưới dạng một dòng JSON kết thúc bằng '\n' trên một Stream (TCP).
/// Đơn giản, dễ debug (đọc được bằng mắt), đủ dùng cho quy mô đồ án.
/// </summary>
public static class WireCodec
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    public static Packet MakePacket<T>(PacketType type, T payload) => new()
    {
        Type = type,
        PayloadJson = JsonSerializer.Serialize(payload, JsonOpts),
    };

    public static T ReadPayload<T>(Packet p) =>
        JsonSerializer.Deserialize<T>(p.PayloadJson, JsonOpts)
        ?? throw new InvalidDataException($"Không thể phân tích payload cho {typeof(T).Name}.");

    public static async Task WritePacketAsync(Stream stream, Packet packet, CancellationToken ct = default)
    {
        var line = JsonSerializer.Serialize(packet, JsonOpts);
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>Đọc một dòng JSON đầy đủ (kết thúc bằng '\n') và phân tích thành Packet. Trả null nếu kết nối đóng.</summary>
    public static async Task<Packet?> ReadPacketAsync(Stream stream, StreamReadBuffer buffer, CancellationToken ct = default)
    {
        string? line = await buffer.ReadLineAsync(stream, ct);
        if (line == null) return null;
        return JsonSerializer.Deserialize<Packet>(line, JsonOpts);
    }
}

/// <summary>Bộ đệm đọc theo dòng đơn giản trên một NetworkStream (vì NetworkStream không hỗ trợ StreamReader an toàn cho ReadLine bất đồng bộ có huỷ).</summary>
public sealed class StreamReadBuffer
{
    private readonly byte[] _buf = new byte[8192];
    private int _len;
    private int _pos;
    private readonly MemoryStream _pending = new();

    public async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        while (true)
        {
            // Tìm '\n' trong phần còn lại của bộ đệm hiện tại
            var pendingArr = _pending.GetBuffer();
            int pendingLen = (int)_pending.Length;
            int nl = Array.IndexOf(pendingArr, (byte)'\n', 0, pendingLen);
            if (nl >= 0)
            {
                var line = Encoding.UTF8.GetString(pendingArr, 0, nl);
                var rest = new byte[pendingLen - nl - 1];
                Array.Copy(pendingArr, nl + 1, rest, 0, rest.Length);
                _pending.SetLength(0);
                _pending.Write(rest);
                return line;
            }

            int read = await stream.ReadAsync(_buf.AsMemory(0, _buf.Length), ct);
            if (read == 0) return _pending.Length > 0 ? FlushRemainder() : null;
            _pending.Write(_buf, 0, read);
        }
    }

    private string FlushRemainder()
    {
        var s = Encoding.UTF8.GetString(_pending.GetBuffer(), 0, (int)_pending.Length);
        _pending.SetLength(0);
        return s;
    }
}
