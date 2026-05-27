using System.Security.Cryptography;

public static class UserStore
{
    // In-memory "database" – i produktion ville dette være en rigtig database
    private static readonly Dictionary<string, string> _users = new();

    public static string HashPassword(string password)
    {
        // PBKDF2 med SHA256, 100.000 iterationer, 32 bytes salt og hash
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        // Gem som "salt:hash" i base64
        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split(':');
        if (parts.Length != 2) return false;

        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] expectedHash = Convert.FromBase64String(parts[1]);

        byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        // CryptographicOperations.FixedTimeEquals forhindrer timing attacks
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    public static bool Register(string username, string password)
    {
        lock (_users)
        {
            if (_users.ContainsKey(username)) return false;
            _users[username] = HashPassword(password);
            return true;
        }
    }

    public static bool Login(string username, string password)
    {
        lock (_users)
        {
            if (!_users.TryGetValue(username, out var stored)) return false;
            return VerifyPassword(password, stored);
        }
    }
}