using System.Text.RegularExpressions;

namespace SecureChat.Core.Services;

/// <summary>Chuẩn hóa và validate số điện thoại di động Việt Nam về dạng +84xxxxxxxxx.</summary>
public static partial class PhoneUtil
{
    // Chấp nhận 0xxxxxxxxx, 84xxxxxxxxx hoặc +84xxxxxxxxx, đầu số di động 3/5/7/8/9.
    [GeneratedRegex(@"^(?:0|\+?84)(3\d{8}|5\d{8}|7\d{8}|8\d{8}|9\d{8})$")]
    private static partial Regex VnMobileRegex();

    /// <summary>Thử chuẩn hóa; trả về false nếu không phải số di động VN hợp lệ.</summary>
    public static bool TryNormalize(string? input, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(input)) return false;

        var cleaned = input.Trim().Replace(" ", "").Replace("-", "").Replace(".", "");
        var match = VnMobileRegex().Match(cleaned);
        if (!match.Success) return false;

        normalized = "+84" + match.Groups[1].Value;
        return true;
    }
}