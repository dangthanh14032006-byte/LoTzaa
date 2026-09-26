namespace SecureChat.Web.Services;

/// <summary>
/// Dịch vụ OTP CHẾ ĐỘ DEMO: sinh mã 6 số, lưu tạm trong bộ nhớ tiến trình (mất khi restart),
/// KHÔNG gửi SMS thật. Mã được trả thẳng về cho client để hiển thị lên màn hình.
/// </summary>
public sealed class OtpService
{
    private sealed class Entry
    {
        public required string Code;
        public DateTime ExpiresAtUtc;
        public DateTime NextResendAtUtc;
        public int Attempts;
    }

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ResendCooldown = TimeSpan.FromSeconds(30);
    private const int MaxVerifyAttempts = 5;

    private readonly Dictionary<string, Entry> _codes = new();
    private readonly object _lock = new();

    public string? GenerateCode(string normalizedPhone, out TimeSpan retryAfter)
    {
        lock (_lock)
        {
            if (_codes.TryGetValue(normalizedPhone, out var existing) &&
                DateTime.UtcNow < existing.NextResendAtUtc)
            {
                retryAfter = existing.NextResendAtUtc - DateTime.UtcNow;
                return null;
            }

            var code = System.Security.Cryptography.RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
            _codes[normalizedPhone] = new Entry
            {
                Code = code,
                ExpiresAtUtc = DateTime.UtcNow.Add(Ttl),
                NextResendAtUtc = DateTime.UtcNow.Add(ResendCooldown),
                Attempts = 0,
            };
            retryAfter = TimeSpan.Zero;
            return code;
        }
    }

    public bool Verify(string normalizedPhone, string code, out string error)
    {
        lock (_lock)
        {
            if (!_codes.TryGetValue(normalizedPhone, out var entry))
            {
                error = "Vui lòng bấm \"Gửi mã OTP\" trước.";
                return false;
            }

            if (DateTime.UtcNow > entry.ExpiresAtUtc)
            {
                _codes.Remove(normalizedPhone);
                error = "Mã OTP đã hết hạn, vui lòng gửi lại.";
                return false;
            }

            entry.Attempts++;
            if (entry.Attempts > MaxVerifyAttempts)
            {
                _codes.Remove(normalizedPhone);
                error = "Sai quá nhiều lần, vui lòng bấm gửi lại mã mới.";
                return false;
            }

            if (!string.Equals(entry.Code, code?.Trim(), StringComparison.Ordinal))
            {
                error = "Mã OTP không đúng.";
                return false;
            }

            _codes.Remove(normalizedPhone);
            error = "";
            return true;
        }
    }
}