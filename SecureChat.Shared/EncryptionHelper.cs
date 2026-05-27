using System.Security.Cryptography;
using System.Text;

public static class EncryptionHelper
{
    // Generer en delt nøgle – i produktion ville denne udveksles via Diffie-Hellman
    public static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(32); // 256-bit

    public static string Encrypt(string plaintext, byte[] key)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize); // 12 bytes
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize]; // 16 bytes
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[plaintextBytes.Length];

        using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Kombiner nonce + tag + ciphertext og returner som base64
        var result = new byte[nonce.Length + tag.Length + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, nonce.Length);
        ciphertext.CopyTo(result, nonce.Length + tag.Length);

        return Convert.ToBase64String(result);
    }

    public static string Decrypt(string encryptedBase64, byte[] key)
    {
        byte[] data = Convert.FromBase64String(encryptedBase64);

        int nonceSize = AesGcm.NonceByteSizes.MaxSize;
        int tagSize = AesGcm.TagByteSizes.MaxSize;

        byte[] nonce = data[..nonceSize];
        byte[] tag = data[nonceSize..(nonceSize + tagSize)];
        byte[] ciphertext = data[(nonceSize + tagSize)..];
        byte[] plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, tagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }
}