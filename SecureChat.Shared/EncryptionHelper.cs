using System.Security.Cryptography;
using System.Text;

public static class EncryptionHelper
{
    // Generer RSA nøglepar – kaldes af klienten ved opstart
    public static RSA GenerateKeyPair() => RSA.Create(2048);

    // Eksportér public key som base64 string – sendes til server
    public static string ExportPublicKey(RSA rsa)
        => Convert.ToBase64String(rsa.ExportRSAPublicKey());

    // Importér en public key fra base64 string – bruges til at kryptere
    public static RSA ImportPublicKey(string base64)
    {
        var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(Convert.FromBase64String(base64), out _);
        return rsa;
    }

    // Kryptér besked med modtagerens public key
    public static string Encrypt(string plaintext, RSA recipientPublicKey)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        var encrypted = recipientPublicKey.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encrypted);
    }

    // Dekryptér besked med egen private key
    public static string Decrypt(string ciphertext, RSA privateKey)
    {
        var data = Convert.FromBase64String(ciphertext);
        var decrypted = privateKey.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decrypted);
    }

    // Signér besked med egen private key
    public static string Sign(string message, RSA privateKey)
    {
        var data = Encoding.UTF8.GetBytes(message);
        var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    // Verificér signatur med afsenderens public key
    public static bool Verify(string message, string signature, RSA senderPublicKey)
    {
        var data = Encoding.UTF8.GetBytes(message);
        var sig = Convert.FromBase64String(signature);
        return senderPublicKey.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}