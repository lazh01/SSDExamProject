using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var tcpClient = new TcpClient();
await tcpClient.ConnectAsync("127.0.0.1", 9000);

var sslStream = new SslStream(
    tcpClient.GetStream(),
    false,
    ValidateServerCertificate
);

await sslStream.AuthenticateAsClientAsync("localhost");
Console.WriteLine($"Connected with TLS. Protocol: {sslStream.SslProtocol}");
Console.WriteLine("Type messages:");

_ = ReceiveMessagesAsync(sslStream);

while (true)
{
    var input = Console.ReadLine();
    if (string.IsNullOrEmpty(input)) continue;

    var data = Encoding.UTF8.GetBytes(input);
    await sslStream.WriteAsync(data);
}

static async Task ReceiveMessagesAsync(SslStream stream)
{
    var buffer = new byte[4096];
    while (true)
    {
        int bytesRead = await stream.ReadAsync(buffer);
        if (bytesRead == 0) break;
        Console.WriteLine($"[Received]: {Encoding.UTF8.GetString(buffer, 0, bytesRead)}");
    }
}

static bool ValidateServerCertificate(object sender, X509Certificate? cert,
    X509Chain? chain, SslPolicyErrors errors)
{
    if (errors == SslPolicyErrors.None) return true;

    // Accepter self-signed cert i dev
    Console.WriteLine($"[Dev mode] Accepting cert with errors: {errors}");
    return true;
}