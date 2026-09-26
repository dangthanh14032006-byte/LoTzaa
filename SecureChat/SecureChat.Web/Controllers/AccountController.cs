using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using SecureChat.Core.Services;
using SecureChat.Core.Crypto;
using System.Security.Cryptography;

namespace SecureChat.Web.Controllers;

public class AccountController : Controller
{
    private readonly UserStore _userStore;
    private readonly SecureChat.Web.Services.KeySessionCache _keyCache;
    private readonly SecureChat.Web.Services.OtpService _otpService;
    public AccountController(
        UserStore userStore,
        SecureChat.Web.Services.KeySessionCache keyCache,
        SecureChat.Web.Services.OtpService otpService)
    {
        _userStore = userStore;
        _keyCache = keyCache;
        _otpService = otpService;
    }

    // =========================================================
    // REGISTER - GET
    // =========================================================

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    // =========================================================
    // REGISTER - POST
    // =========================================================
    [HttpPost]
    public IActionResult SendOtp([FromForm] string phoneNumber)
    {
        if (!SecureChat.Core.Services.PhoneUtil.TryNormalize(phoneNumber, out var normalized))
            return Json(new { ok = false, error = "Số điện thoại không hợp lệ." });

        if (_userStore.PhoneNumberTaken(normalized))
            return Json(new { ok = false, error = "Số điện thoại đã được đăng ký." });

        var code = _otpService.GenerateCode(normalized, out var retryAfter);
        if (code == null)
            return Json(new { ok = false, error = $"Vui lòng đợi {Math.Ceiling(retryAfter.TotalSeconds)} giây trước khi gửi lại." });

        return Json(new { ok = true, phoneNumber = normalized, demoCode = code });
    }
    [HttpPost]
    public IActionResult Register(
    string username,
    string password,
    string confirmPassword,
    string phoneNumber,
    string otpCode)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            ViewBag.Error = "Vui lòng nhập tên đăng nhập.";
            return View();
        }

        if (password != confirmPassword)
        {
            ViewBag.Error = "Mật khẩu nhập lại không khớp.";
            return View();
        }
        if (!SecureChat.Core.Services.PhoneUtil.TryNormalize(phoneNumber, out var normalizedPhone))
        {
            ViewBag.Error = "Số điện thoại không hợp lệ.";
            return View();
        }

        if (!_otpService.Verify(normalizedPhone, otpCode ?? "", out var otpError))
        {
            ViewBag.Error = otpError;
            return View();
        }
        try
        {
            // =================================================
            // 1. TẠO ELGAMAL KEY
            // =================================================

            var elgamalKeys = ElGamal.GenerateKeyPair();

            // =================================================
            // 2. TẠO RSA KEY 2048 BIT
            // =================================================

            var rsaKeys = RsaCipher.GenerateKeyPair();

            // =================================================
            // 3. MÃ HÓA ELGAMAL PRIVATE KEY BẰNG PASSWORD
            // =================================================

            var keySalt =
                RandomNumberGenerator.GetBytes(16);

            var kek =
                HashUtil.Pbkdf2(
                    password,
                    keySalt,
                    200_000,
                    AesGcmCipher.KeySize);

            var encryptedElgamalPrivate =
                AesGcmCipher.Encrypt(
                    kek,
                    BigIntUtil.ToBytes(
                        elgamalKeys.PrivateKeyX));

            // =================================================
            // 4. MÃ HÓA RSA PRIVATE KEY BẰNG PASSWORD
            // =================================================

            var rsaKeySalt =
                RandomNumberGenerator.GetBytes(16);

            var rsaKek =
                HashUtil.Pbkdf2(
                    password,
                    rsaKeySalt,
                    200_000,
                    AesGcmCipher.KeySize);

            var encryptedRsaPrivate =
                AesGcmCipher.Encrypt(
                    rsaKek,
                    rsaKeys.PrivateKey);

            // =================================================
            // 5. CHUYỂN PUBLIC KEY SANG BASE64
            // =================================================

            var elgamalPublicKeyB64 =
                BigIntUtil.ToB64(
                    elgamalKeys.PublicKeyY);

            var rsaPublicKeyB64 =
                Convert.ToBase64String(
                    rsaKeys.PublicKey);

            // =================================================
            // 6. ĐĂNG KÝ USER
            // =================================================

            var result =
    _userStore.TryRegister(
        username,
        password,
        normalizedPhone,
        elgamalPublicKeyB64,
        out var error,
        rsaPublicKeyB64);

            if (!result)
            {
                ViewBag.Error = error;
                return View();
            }

            // =================================================
            // 7. LƯU CẢ ELGAMAL + RSA KEY
            // =================================================

            var saved =
                _userStore.SaveKeys(
                    username,

                    // ElGamal
                    elgamalPublicKeyB64,
                    Convert.ToBase64String(
                        encryptedElgamalPrivate),
                    Convert.ToBase64String(
                        keySalt),
                    200_000,

                    // RSA
                    rsaPublicKeyB64,
                    Convert.ToBase64String(
                        encryptedRsaPrivate),
                    Convert.ToBase64String(
                        rsaKeySalt),
                    200_000);

            if (!saved)
            {
                ViewBag.Error =
                    "Đăng ký thất bại khi lưu khóa.";

                return View();
            }

            ViewBag.Success =
                "Đăng ký thành công! Bạn có thể đăng nhập.";

            ViewBag.RegisteredUser = username;

            return View();
        }
        catch (Exception ex)
        {
            ViewBag.Error =
                "Lỗi khi tạo khóa: " + ex.Message;

            return View();
        }
    }

    // =========================================================
    // LOGIN - GET
    // =========================================================

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    // =========================================================
    // LOGIN - POST
    // =========================================================

    [HttpPost]
    public async Task<IActionResult> Login(
        string username,
        string password)
    {
        // =====================================================
        // 1. KIỂM TRA USER + PASSWORD
        // =====================================================
        var resolvedUsername = _userStore.ResolveIdentifierToUsername(username);
        if (resolvedUsername == null)
        {
            ViewBag.Error = "Sai tên đăng nhập hoặc mật khẩu.";
            return View();
        }
        username = resolvedUsername;
        var result =
            _userStore.TryLogin(
                username,
                password,
                out var error);

        if (!result)
        {
            ViewBag.Error = error;
            return View();
        }

        try
        {
            // =================================================
            // 2. LẤY ACCOUNT
            // =================================================

            var account =
                _userStore.Find(username);

            if (account == null)
            {
                ViewBag.Error =
                    "Không tìm thấy tài khoản.";

                return View();
            }

            // =================================================
            // 3. KIỂM TRA RSA KEY
            // =================================================

            if (string.IsNullOrWhiteSpace(
                    account.RsaPublicKeyB64))
            {
                ViewBag.Error =
                    "Tài khoản chưa có RSA Public Key. " +
                    "Vui lòng đăng ký lại tài khoản.";

                return View();
            }

            if (string.IsNullOrWhiteSpace(
                    account.RsaEncryptedPrivateKeyB64))
            {
                ViewBag.Error =
                    "Tài khoản chưa có RSA Private Key.";

                return View();
            }

            // =================================================
            // 4. GIẢI MÃ ELGAMAL PRIVATE KEY
            // =================================================

            var loginSalt =
                Convert.FromBase64String(
                    account.KeySaltB64);

            var loginKek =
                HashUtil.Pbkdf2(
                    password,
                    loginSalt,
                    account.KeyIterations,
                    AesGcmCipher.KeySize);

            var privBytes =
                AesGcmCipher.Decrypt(
                    loginKek,
                    Convert.FromBase64String(
                        account.EncryptedPrivateKeyB64));

            var elgamalPrivate =
                BigIntUtil.FromBytes(
                    privBytes);

            // =================================================
            // 5. GIẢI MÃ RSA PRIVATE KEY
            // =================================================

            var rsaSalt =
                Convert.FromBase64String(
                    account.RsaKeySaltB64);

            var rsaKek =
                HashUtil.Pbkdf2(
                    password,
                    rsaSalt,
                    account.RsaKeyIterations,
                    AesGcmCipher.KeySize);

            var rsaPrivate =
                AesGcmCipher.Decrypt(
                    rsaKek,
                    Convert.FromBase64String(
                        account.RsaEncryptedPrivateKeyB64));

            // =================================================
            // 6. LƯU KEY VÀO SESSION CACHE
            // =================================================

            _keyCache.Set(
                username,
                new ElGamalKeyPair
                {
                    PrivateKeyX =
                        elgamalPrivate,

                    PublicKeyY =
                        BigIntUtil.FromB64(
                            account.PublicKeyB64),

                    Rsa =
                        new RsaKeyPair
                        {
                            PublicKey =
                                Convert.FromBase64String(
                                    account.RsaPublicKeyB64),

                            PrivateKey =
                                rsaPrivate
                        }
                });

            // =================================================
            // 7. TẠO LOGIN COOKIE
            // =================================================

            var claims =
                new List<System.Security.Claims.Claim>
                {
                    new(
                        System.Security.Claims.ClaimTypes.NameIdentifier,
                        username),

                    new(
                        System.Security.Claims.ClaimTypes.Name,
                        username)
                };

            var identity =
                new System.Security.Claims.ClaimsIdentity(
                    claims,
                    "SecureChatCookie");

            var principal =
                new System.Security.Claims.ClaimsPrincipal(
                    identity);

            await HttpContext.SignInAsync(
                "SecureChatCookie",
                principal);

            // =================================================
            // 8. CHUYỂN SANG TRANG CHAT
            // =================================================

            return RedirectToAction(
                "Index",
                "Chat");
        }
        catch (Exception ex)
        {
            ViewBag.Error =
                "Lỗi khi khôi phục khóa: " +
                ex.Message;

            return View();
        }
    }

    // =========================================================
    // LOGOUT
    // =========================================================

    public async Task<IActionResult> Logout()
    {
        var username =
            User.Identity?.Name;

        if (username != null)
        {
            _keyCache.Remove(username);
        }

        await HttpContext.SignOutAsync(
            "SecureChatCookie");

        return RedirectToAction(
            "Login");
    }
}