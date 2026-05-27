using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

var clients = new Dictionary<string, SslStream>();
var publicKeys = new Dictionary<string, string>(); // brugernavn -> public key (base64)

var cert = CertHelper.GetOrCreateCertificate("server.pfx", "supersecret123");
var listener = new TcpListener(IPAddress.Any, 9000);
listener.Start();
Console.WriteLine("Server listening on port 9000 (TLS)...");

while (true)
{
    var tcpClient = await listener.AcceptTcpClientAsync();
    Console.WriteLine($"Client connected: {tcpClient.Client.RemoteEndPoint}");
    _ = HandleClientAsync(tcpClient, cert, clients, publicKeys);
}

static async Task HandleClientAsync(TcpClient tcpClient, X509Certificate2 cert,
    Dictionary<string, SslStream> clients, Dictionary<string, string> publicKeys)
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

        // Auth
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

        bool authenticated;
        lock (clients)
        {
            if (!clients.ContainsKey(username))
                authenticated = UserStore.Register(username, password);
            else
                authenticated = false;
        }

        if (!authenticated)
            authenticated = UserStore.Login(username, password);

        if (!authenticated)
        {
            await MessageProtocol.SendMessageAsync(sslStream, "error", "Authentication failed");
            return;
        }

        await MessageProtocol.SendMessageAsync(sslStream, "auth_ok", $"Welcome {username}!");

        // Modtag klientens public key
        var keyMsg = await MessageProtocol.ReadMessageAsync(sslStream);
        if (keyMsg == null || keyMsg.Value.type != "pubkey")
        {
            await MessageProtocol.SendMessageAsync(sslStream, "error", "Expected public key");
            return;
        }

        lock (clients)
        {
            clients[username] = sslStream;
            publicKeys[username] = keyMsg.Value.payload;
        }
        addedToClients = true;

        lock (publicKeys)
        {
            foreach (var (user, pubKey) in publicKeys.Where(k => k.Key != username))
            {
                MessageProtocol.SendMessageAsync(sslStream, "pubkey_response", $"{user}:{pubKey}").Wait();
            }
        }

        Console.WriteLine($"User authenticated: {username}");
        await BroadcastAsync(clients, publicKeys, username, $"{username} joined the chat", isSystem: true);

        // Modtag beskeder
        while (true)
        {
            var received = await MessageProtocol.ReadMessageAsync(sslStream);
            if (received == null) break;

            // Klient beder om en anden brugers public key
            if (received.Value.type == "get_pubkey")
            {
                var requestedUser = received.Value.payload;
                lock (publicKeys)
                {
                    if (publicKeys.TryGetValue(requestedUser, out var pubKey))
                        MessageProtocol.SendMessageAsync(sslStream, "pubkey_response", $"{requestedUser}:{pubKey}").Wait();
                    else
                        MessageProtocol.SendMessageAsync(sslStream, "error", $"User {requestedUser} not found").Wait();
                }
            }

            // Relay krypteret besked videre til modtager
            else if (received.Value.type == "message")
            {
                // Format: "modtager|ciphertext|signature"
                var messageParts = received.Value.payload.Split('|', 3);
                if (messageParts.Length != 3) continue;

                var recipient = messageParts[0];
                var payload = $"{username}|{messageParts[1]}|{messageParts[2]}";

                SslStream? recipientStream;
                lock (clients) clients.TryGetValue(recipient, out recipientStream);

                if (recipientStream != null)
                {
                    try
                    {
                        await MessageProtocol.SendMessageAsync(recipientStream, "message", payload);
                    }
                    catch { }
                }
                else
                {
                    await MessageProtocol.SendMessageAsync(sslStream, "error", $"{recipient} is not online");
                }
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
                publicKeys.Remove(username);
            }
            await BroadcastAsync(clients, publicKeys, username, $"{username} left the chat", isSystem: true);
        }
        sslStream.Dispose();
        tcpClient.Dispose();
    }
}

static async Task BroadcastAsync(Dictionary<string, SslStream> clients,
    Dictionary<string, string> publicKeys, string sender, string message, bool isSystem = false)
{
    List<KeyValuePair<string, SslStream>> snapshot;
    lock (clients) snapshot = clients.Where(c => isSystem || c.Key != sender).ToList();

    foreach (var (user, stream) in snapshot)
    {
        try
        {
            await MessageProtocol.SendMessageAsync(stream, "system", message);
        }
        catch { }
    }
}