using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

Console.Write("Enter username: ");
var username = Console.ReadLine()?.Trim();

Console.Write("Enter password: ");
var password = Console.ReadLine()?.Trim();

if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
{
    Console.WriteLine("Username and password cannot be empty.");
    return;
}

var tcpClient = new TcpClient();
await tcpClient.ConnectAsync("127.0.0.1", 9000);

var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate);
await sslStream.AuthenticateAsClientAsync("localhost");
Console.WriteLine($"Connected with TLS. Protocol: {sslStream.SslProtocol}");

// Send brugernavn + password til server
await MessageProtocol.SendMessageAsync(sslStream, "auth", $"{username}:{password}");

// Vent på server-bekræftelse
var response = await MessageProtocol.ReadMessageAsync(sslStream);
if (response == null || response.Value.type == "error")
{
    Console.WriteLine($"Auth failed: {response?.payload ?? "no response"}");
    return;
}

Console.WriteLine(response.Value.payload); // "Welcome Alice!"

// Modtag delt nøgle fra server
var keyMsg = await MessageProtocol.ReadMessageAsync(sslStream);
if (keyMsg == null || keyMsg.Value.type != "key")
{
    Console.WriteLine("Did not receive encryption key.");
    return;
}
var sharedKey = Convert.FromBase64String(keyMsg.Value.payload);

Console.WriteLine("Type messages (or 'quit' to exit):");

_ = ReceiveMessagesAsync(sslStream, sharedKey);

while (true)
{
    var input = Console.ReadLine();
    if (string.IsNullOrEmpty(input)) continue;
    if (input == "quit") break;

    var encrypted = EncryptionHelper.Encrypt(input, sharedKey);
    await MessageProtocol.SendMessageAsync(sslStream, "message", encrypted);
}

static async Task ReceiveMessagesAsync(SslStream stream, byte[] key)
{
    while (true)
    {
        var msg = await MessageProtocol.ReadMessageAsync(stream);
        if (msg == null) break;

        if (msg.Value.type == "message")
        {
            var text = EncryptionHelper.Decrypt(msg.Value.payload, key);
            Console.WriteLine(text);
        }
    }
}

static bool ValidateServerCertificate(object sender, X509Certificate? cert,
    X509Chain? chain, SslPolicyErrors errors)
{
    if (errors == SslPolicyErrors.None) return true;
    Console.WriteLine($"[Dev mode] Accepting cert with errors: {errors}");
    return true;
}