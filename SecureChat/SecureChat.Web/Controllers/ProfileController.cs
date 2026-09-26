using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureChat.Core.Services;
using SecureChat.Web.Models;
using Microsoft.AspNetCore.Localization;
namespace SecureChat.Web.Controllers;

[Authorize]
public sealed class ProfileController : Controller
{
    private const long MaxAvatarBytes = 2 * 1024 * 1024;

    private readonly UserStore _users;
    private readonly IWebHostEnvironment _environment;

    public ProfileController(UserStore users, IWebHostEnvironment environment)
    {
        _users = users;
        _environment = environment;
    }

    [HttpGet]
    public IActionResult Details(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return NotFound();

        var account = _users.Find(username);
        if (account == null)
            return NotFound();

        // Chỉ đưa các trường công khai ra view, không truyền toàn bộ UserAccount.
        var model = new ProfileDetailsViewModel
        {
            Username = account.Username,
            DisplayName = string.IsNullOrWhiteSpace(account.DisplayName)
                ? account.Username
                : account.DisplayName,
            Bio = account.Bio ?? "",
            AvatarUrl = account.AvatarUrl ?? ""
        };

        return View(model);
    }

    [HttpGet]
    public IActionResult Edit()
    {
        var account = GetCurrentAccount();
        if (account == null)
            return Challenge();

        return View(new ProfileEditViewModel
        {
            DisplayName = string.IsNullOrWhiteSpace(account.DisplayName)
        ? account.Username
        : account.DisplayName,
            Bio = account.Bio ?? "",
            AvatarUrl = account.AvatarUrl ?? "",

            PhoneNumber = account.PhoneNumber ?? "",
            Email = account.Email ?? "",
            DateOfBirth = account.DateOfBirth,
            Language = string.IsNullOrWhiteSpace(account.Language)
        ? "vi"
        : account.Language
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(ProfileEditViewModel model)
    {
        var account = GetCurrentAccount();
        if (account == null)
            return Challenge();

        model.AvatarUrl = account.AvatarUrl ?? "";

        if (!ModelState.IsValid)
            return View(model);

        var avatarUrl = model.AvatarUrl;

        if (model.Avatar is { Length: > 0 } avatar)
        {
            if (avatar.Length > MaxAvatarBytes)
            {
                ModelState.AddModelError(
                    nameof(model.Avatar),
                    "Ảnh đại diện phải nhỏ hơn hoặc bằng 2 MB.");
                return View(model);
            }

            var extension = Path.GetExtension(avatar.FileName).ToLowerInvariant();
            var expectedContentType = extension switch
            {
                ".jpg" or ".jpeg" => "image/jpeg",
                ".png" => "image/png",
                ".webp" => "image/webp",
                _ => null
            };

            if (expectedContentType == null ||
                !string.Equals(avatar.ContentType, expectedContentType,
                    StringComparison.OrdinalIgnoreCase) ||
                !await HasAllowedImageSignature(avatar, extension))
            {
                ModelState.AddModelError(
                    nameof(model.Avatar),
                    "Chỉ nhận ảnh JPEG, PNG hoặc WebP hợp lệ.");
                return View(model);
            }

            var webRoot = _environment.WebRootPath;
            if (string.IsNullOrWhiteSpace(webRoot))
                webRoot = Path.Combine(_environment.ContentRootPath, "wwwroot");

            var uploadDirectory = Path.Combine(webRoot, "uploads", "avatars");
            Directory.CreateDirectory(uploadDirectory);

            var fileName = Guid.NewGuid().ToString("N") + extension;
            var fullPath = Path.Combine(uploadDirectory, fileName);

            await using (var fileStream = new FileStream(
                fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await avatar.CopyToAsync(fileStream);
            }

            avatarUrl = "/uploads/avatars/" + fileName;
            model.AvatarUrl = avatarUrl;
        }

        var saved = _users.UpdateProfile(
    account.Username,
    model.DisplayName,
    model.Bio ?? "",
    avatarUrl,
    model.PhoneNumber,
    model.Email,
    model.DateOfBirth,
    model.Language,
    out var updateError);

        if (!saved)
        {
            ModelState.AddModelError(
                nameof(model.PhoneNumber),
                updateError);

            return View(model);
        }
        var culture = model.Language == "en" ? "en" : "vi";

        Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(
                new RequestCulture(culture)),
            new CookieOptions
            {
                Expires = DateTimeOffset.UtcNow.AddYears(1),
                IsEssential = true,
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Lax
            });
        return RedirectToAction(nameof(Edit));
    }

    private SecureChat.Core.Services.UserAccount? GetCurrentAccount()
    {
        var username = User.Identity?.Name;
        return string.IsNullOrWhiteSpace(username)
            ? null
            : _users.Find(username);
    }

    private static async Task<bool> HasAllowedImageSignature(
        IFormFile file,
        string extension)
    {
        var header = new byte[12];
        var count = 0;

        await using (var stream = file.OpenReadStream())
        {
            while (count < header.Length)
            {
                var read = await stream.ReadAsync(header.AsMemory(count));
                if (read == 0)
                    break;

                count += read;
            }
        }

        var isJpeg = count >= 3 &&
                     header[0] == 0xFF &&
                     header[1] == 0xD8 &&
                     header[2] == 0xFF;

        var isPng = count >= 8 &&
                    header[0] == 0x89 &&
                    header[1] == 0x50 &&
                    header[2] == 0x4E &&
                    header[3] == 0x47 &&
                    header[4] == 0x0D &&
                    header[5] == 0x0A &&
                    header[6] == 0x1A &&
                    header[7] == 0x0A;

        var isWebp = count >= 12 &&
                     header[0] == (byte)'R' &&
                     header[1] == (byte)'I' &&
                     header[2] == (byte)'F' &&
                     header[3] == (byte)'F' &&
                     header[8] == (byte)'W' &&
                     header[9] == (byte)'E' &&
                     header[10] == (byte)'B' &&
                     header[11] == (byte)'P';

        return extension switch
        {
            ".jpg" or ".jpeg" => isJpeg,
            ".png" => isPng,
            ".webp" => isWebp,
            _ => false
        };
    }
}
