using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class CertHelper
{
    public static X509Certificate2 GetOrCreateCertificate(string pfxPath, string password)
    {
        if (File.Exists(pfxPath))
            return new X509Certificate2(pfxPath, password);

        Console.WriteLine("Generating self-signed certificate...");

        using var rsa = RSA.Create(4096);
        var request = new CertificateRequest(
            "CN=localhost",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(365));

        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(pfxPath, pfxBytes);
        Console.WriteLine($"Certificate saved to {pfxPath}");

        return new X509Certificate2(pfxBytes, password);
    }
}