using System.Security.Cryptography;
using System.Text.Json;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.Services;

public sealed class UserAccount
{

    public string Username { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Bio { get; set; } = "";
    public string AvatarUrl { get; set; } = "";
    public string PhoneNumber { get; set; } = "";
    public string SaltB64 { get; set; } = "";
    public int Iterations { get; set; }
    public string PasswordHashB64 { get; set; } = "";
    public string KeySaltB64 { get; set; } = "";
    public int KeyIterations { get; set; }
    public string EncryptedPrivateKeyB64 { get; set; } = "";
    public string PublicKeyB64 { get; set; } = "";
    public string RsaPublicKeyB64 { get; set; } = "";
    public string RsaEncryptedPrivateKeyB64 { get; set; } = "";
    public string RsaKeySaltB64 { get; set; } = "";
    public int RsaKeyIterations { get; set; }

    public string Email { get; set; } = "";
    public DateTime? DateOfBirth { get; set; }
    public string Language { get; set; } = "vi";
}

public sealed class UserStore
{
    private const int Pbkdf2Iterations = 200_000;

    private readonly string _path;

    private readonly Dictionary<string, UserAccount> _users =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly object _lock = new();

    public UserStore(string path)
    {
        _path = path;
        Load();
    }

    private void Load()
    {
        if (!File.Exists(_path))
            return;

        var list =
            JsonSerializer.Deserialize<List<UserAccount>>(
                File.ReadAllText(_path)
            ) ?? new();

        foreach (var user in list)
            _users[user.Username] = user;
    }

    private void Persist()
    {
        var directory =
            Path.GetDirectoryName(
                Path.GetFullPath(_path)
            );

        if (directory != null)
            Directory.CreateDirectory(directory);

        File.WriteAllText(
            _path,
            JsonSerializer.Serialize(_users.Values.ToList())
        );
    }

    public bool TryRegister(
string username,
string password,
string phoneNumber,
string publicKeyB64,
out string error,
string rsaPublicKeyB64 = "")
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(username) ||
                username.Length < 3)
            {
                error = "Tên đăng nhập phải có ít nhất 3 ký tự.";
                return false;
            }

            if (password.Length < 6)
            {
                error = "Mật khẩu phải có ít nhất 6 ký tự.";
                return false;
            }
            string normalizedPhone = "";
            if (!string.IsNullOrWhiteSpace(phoneNumber))
            {
                if (!PhoneUtil.TryNormalize(phoneNumber, out normalizedPhone))
                {
                    error = "Số điện thoại không hợp lệ.";
                    return false;
                }

                if (_users.Values.Any(u => u.PhoneNumber == normalizedPhone))
                {
                    error = "Số điện thoại đã được đăng ký.";
                    return false;
                }
            }
            if (_users.ContainsKey(username))
            {
                error = "Tên đăng nhập đã tồn tại.";
                return false;
            }

            var salt =
                RandomNumberGenerator.GetBytes(16);

            var hash =
                HashUtil.Pbkdf2(
                    password,
                    salt,
                    Pbkdf2Iterations,
                    32
                );

            _users[username] = new UserAccount
            {
                Username = username,
                PhoneNumber = normalizedPhone,
                SaltB64 =
                    Convert.ToBase64String(salt),

                Iterations =
                    Pbkdf2Iterations,

                PasswordHashB64 =
                    Convert.ToBase64String(hash),

                PublicKeyB64 =
    publicKeyB64,

                RsaPublicKeyB64 =
    rsaPublicKeyB64
            };

            Persist();

            error = "";
            return true;
        }
    }

    public bool TryLogin(
        string username,
        string password,
        out string error)
    {
        lock (_lock)
        {
            if (!_users.TryGetValue(username, out var user))
            {
                error = "Sai tên đăng nhập hoặc mật khẩu.";
                return false;
            }

            var salt =
                Convert.FromBase64String(user.SaltB64);

            var hash =
                HashUtil.Pbkdf2(
                    password,
                    salt,
                    user.Iterations,
                    32
                );

            var oldHash =
                Convert.FromBase64String(
                    user.PasswordHashB64
                );

            if (!CryptographicOperations.FixedTimeEquals(
                    hash,
                    oldHash))
            {
                error = "Sai tên đăng nhập hoặc mật khẩu.";
                return false;
            }

            error = "";
            return true;
        }
    }

    public bool SaveKeys(
    string username,
    string publicKeyB64,
    string encryptedPrivateKeyB64,
    string keySaltB64,
    int keyIterations,
    string rsaPublicKeyB64,
    string rsaEncryptedPrivateKeyB64,
    string rsaKeySaltB64,
    int rsaKeyIterations)
    {
        lock (_lock)
        {
            if (!_users.TryGetValue(username, out var user))
                return false;

            // ElGamal
            user.PublicKeyB64 = publicKeyB64;
            user.EncryptedPrivateKeyB64 = encryptedPrivateKeyB64;
            user.KeySaltB64 = keySaltB64;
            user.KeyIterations = keyIterations;

            // RSA
            user.RsaPublicKeyB64 = rsaPublicKeyB64;
            user.RsaEncryptedPrivateKeyB64 = rsaEncryptedPrivateKeyB64;
            user.RsaKeySaltB64 = rsaKeySaltB64;
            user.RsaKeyIterations = rsaKeyIterations;

            Persist();
            return true;
        }
    }
    public UserAccount? Find(string username)
    {
        lock (_lock)
        {
            return _users.TryGetValue(
                username,
                out var user)
                ? user
                : null;
        }
    }
    public string? ResolveIdentifierToUsername(string identifier)
    {
        lock (_lock)
        {
            if (PhoneUtil.TryNormalize(identifier, out var normalizedPhone))
            {
                var byPhone = _users.Values.FirstOrDefault(u => u.PhoneNumber == normalizedPhone);
                if (byPhone != null) return byPhone.Username;
            }

            return _users.ContainsKey(identifier) ? identifier : null;
        }
    }

    public bool PhoneNumberTaken(string normalizedPhone)
    {
        lock (_lock)
        {
            return _users.Values.Any(u => u.PhoneNumber == normalizedPhone);
        }
    }
    public List<string> AllUsernames()
    {
        lock (_lock)
        {
            return _users.Keys.ToList();
        }
    }
    public bool UpdateProfile(
     string username,
     string displayName,
     string bio,
     string avatarUrl,
     string phoneNumber,
     string email,
     DateTime? dateOfBirth,
     string language,
     out string error)
    {
        lock (_lock)
        {
            if (!_users.TryGetValue(username, out var user))
            {
                error = "Không tìm thấy tài khoản.";
                return false;
            }

            string normalizedPhone = "";

            if (!string.IsNullOrWhiteSpace(phoneNumber))
            {
                if (!PhoneUtil.TryNormalize(phoneNumber, out normalizedPhone))
                {
                    error = "Số điện thoại không hợp lệ.";
                    return false;
                }

                bool phoneAlreadyUsed = _users.Values.Any(other =>
                    !other.Username.Equals(
                        username,
                        StringComparison.OrdinalIgnoreCase) &&
                    other.PhoneNumber == normalizedPhone);

                if (phoneAlreadyUsed)
                {
                    error = "Số điện thoại đã được tài khoản khác sử dụng.";
                    return false;
                }
            }

            user.DisplayName = displayName.Trim();
            user.Bio = bio.Trim();
            user.AvatarUrl = avatarUrl;
            user.PhoneNumber = normalizedPhone;
            user.Email = email.Trim();
            user.DateOfBirth = dateOfBirth;
            user.Language = language == "en" ? "en" : "vi";

            Persist();

            error = "";
            return true;
        }
    }
}