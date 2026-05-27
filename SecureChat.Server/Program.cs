using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

var clients = new Dictionary<string, SslStream>();
var clientKeys = new Dictionary<string, byte[]>();

var cert = CertHelper.GetOrCreateCertificate("server.pfx", "supersecret123");
var listener = new TcpListener(IPAddress.Any, 9000);
listener.Start();
Console.WriteLine("Server listening on port 9000 (TLS)...");

while (true)
{
    var tcpClient = await listener.AcceptTcpClientAsync();
    Console.WriteLine($"Client connected: {tcpClient.Client.RemoteEndPoint}");
    _ = HandleClientAsync(tcpClient, cert, clients, clientKeys);
}

static async Task HandleClientAsync(TcpClient tcpClient, X509Certificate2 cert, Dictionary<string, SslStream> clients, Dictionary<string, byte[]> clientKeys)
{
    var sslStream = new SslStream(tcpClient.GetStream(), false);
    string? username = null;
    bool addedToClients = false;

    try
    {
        await sslStream.AuthenticateAsServerAsync(cert,
            clientCertificateRequired: false,
            checkCertificateRevocation: false);

        Console.WriteLine($"TLS handshake OK. Protocol: {sslStream.SslProtocol}");

        // Modtag auth-besked: "brugernavn:password"
        var msg = await MessageProtocol.ReadMessageAsync(sslStream);
        if (msg == null || msg.Value.type != "auth")
        {
            await MessageProtocol.SendMessageAsync(sslStream, "error", "Expected auth message");
            return;
        }

        var parts = msg.Value.payload.Split(':', 2);
        if (parts.Length != 2)
        {
            await MessageProtocol.SendMessageAsync(sslStream, "error", "Invalid auth format");
            return;
        }

        username = parts[0].Trim();
        var password = parts[1];

        if (string.IsNullOrEmpty(username) || username.Length > 20)
        {
            await MessageProtocol.SendMessageAsync(sslStream, "error", "Invalid username");
            return;
        }

        // Registrer bruger hvis ikke findes, ellers login
        bool authenticated;
        lock (clients)
        {
            if (!clients.ContainsKey(username))
                authenticated = UserStore.Register(username, password);
            else
                authenticated = false; // brugernavn optaget
        }

        if (!authenticated)
        {
            // Forsøg login hvis bruger allerede eksisterer
            authenticated = UserStore.Login(username, password);
        }

        if (!authenticated)
        {
            await MessageProtocol.SendMessageAsync(sslStream, "error", "Authentication failed");
            return;
        }

        var clientKey = EncryptionHelper.GenerateKey();
        await MessageProtocol.SendMessageAsync(sslStream, "auth_ok", $"Welcome {username}!");
        await MessageProtocol.SendMessageAsync(sslStream, "key", Convert.ToBase64String(clientKey));

        lock (clients)
        {
            clients[username] = sslStream;
            clientKeys[username] = clientKey;
        }
        addedToClients = true;

        // Broadcast join-besked
        await BroadcastAsync(clients, clientKeys, username, $"{username} joined the chat", isSystem: true);

        // Modtag beskeder
        while (true)
        {
            var received = await MessageProtocol.ReadMessageAsync(sslStream);
            if (received == null) break;

            if (received.Value.type == "message")
            {
                // Dekrypter indkommende besked
                var text = EncryptionHelper.Decrypt(received.Value.payload, clientKey);
                Console.WriteLine($"[{username}]: {text}");
                await BroadcastAsync(clients, clientKeys, username, $"[{username}]: {text}");
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"{username ?? "unknown"} disconnected: {ex.Message}");
    }
    finally
    {
        if (username != null && addedToClients)
        {
            lock (clients)
            {
                clients.Remove(username);
                clientKeys.Remove(username);
            }
            await BroadcastAsync(clients, clientKeys, username, $"{username} left the chat", isSystem: true);
        }
        sslStream.Dispose();
        tcpClient.Dispose();
    }
}

static async Task BroadcastAsync(Dictionary<string, SslStream> clients,
    Dictionary<string, byte[]> clientKeys, string sender, string message, bool isSystem = false)
{
    List<KeyValuePair<string, SslStream>> snapshot;
    lock (clients) snapshot = clients.Where(c => isSystem || c.Key != sender).ToList();

    foreach (var (user, stream) in snapshot)
    {
        try
        {
            var encrypted = EncryptionHelper.Encrypt(message, clientKeys[user]);
            await MessageProtocol.SendMessageAsync(stream, "message", encrypted);
        }
        catch { }
    }
}