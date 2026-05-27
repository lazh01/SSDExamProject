using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Concurrent;

Console.Write("Enter username: ");
var username = Console.ReadLine()?.Trim();

Console.Write("Enter password: ");
var password = Console.ReadLine()?.Trim();

if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
{
    Console.WriteLine("Username and password cannot be empty.");
    return;
}

var rsaKey = EncryptionHelper.GenerateKeyPair();
var myPublicKey = EncryptionHelper.ExportPublicKey(rsaKey);

var tcpClient = new TcpClient();
await tcpClient.ConnectAsync("127.0.0.1", 9000);

var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate);
await sslStream.AuthenticateAsClientAsync("localhost");
Console.WriteLine($"Connected with TLS. Protocol: {sslStream.SslProtocol}");

await MessageProtocol.SendMessageAsync(sslStream, "auth", $"{username}:{password}");

var response = await MessageProtocol.ReadMessageAsync(sslStream);
if (response == null || response.Value.type == "error")
{
    Console.WriteLine($"Auth failed: {response?.payload ?? "no response"}");
    return;
}
Console.WriteLine(response.Value.payload);

await MessageProtocol.SendMessageAsync(sslStream, "pubkey", myPublicKey);
Console.WriteLine("Public key registered with server.");

var keyCache = new Dictionary<string, RSA>();

// Kø til pubkey responses som baggrundslæseren fanger
var pubkeyResponses = new BlockingCollection<string>();

Console.WriteLine("Commands:");
Console.WriteLine("  @username message  - send krypteret besked til bruger");
Console.WriteLine("  quit               - afslut");

// Al læsning sker kun ét sted
_ = ReceiveMessagesAsync(sslStream, rsaKey, keyCache, pubkeyResponses);

while (true)
{
    var input = Console.ReadLine();
    if (string.IsNullOrEmpty(input)) continue;
    if (input == "quit") break;

    if (!input.StartsWith("@"))
    {
        Console.WriteLine("Brug @brugernavn besked for at sende");
        continue;
    }

    var spaceIndex = input.IndexOf(' ');
    if (spaceIndex == -1)
    {
        Console.WriteLine("Mangler besked efter brugernavn");
        continue;
    }

    var recipient = input[1..spaceIndex];
    var message = input[(spaceIndex + 1)..];

    // Hent public key hvis vi ikke har den
    if (!keyCache.ContainsKey(recipient))  // hent kun hvis ikke allerede cachet af baggrundslæseren
    {
        await MessageProtocol.SendMessageAsync(sslStream, "get_pubkey", recipient);

        // Vent på svar fra baggrundslæseren (max 5 sekunder)
        if (!pubkeyResponses.TryTake(out var keyPayload, TimeSpan.FromSeconds(5)))
        {
            Console.WriteLine($"Timeout: kunne ikke hente public key for {recipient}");
            continue;
        }

        var keyParts = keyPayload.Split(':', 2);
        if (keyParts.Length != 2)
        {
            Console.WriteLine($"Ugyldigt key format for {recipient}");
            continue;
        }

        keyCache[keyParts[0]] = EncryptionHelper.ImportPublicKey(keyParts[1]);
        Console.WriteLine($"Public key hentet for {recipient}");
    }

    var encrypted = EncryptionHelper.Encrypt(message, keyCache[recipient]);
    var signature = EncryptionHelper.Sign(message, rsaKey);
    await MessageProtocol.SendMessageAsync(sslStream, "message", $"{recipient}|{encrypted}|{signature}");
}

static async Task ReceiveMessagesAsync(SslStream stream, RSA privateKey,
    Dictionary<string, RSA> keyCache, BlockingCollection<string> pubkeyResponses)
{
    while (true)
    {
        var msg = await MessageProtocol.ReadMessageAsync(stream);
        if (msg == null) break;

        switch (msg.Value.type)
        {
            case "system":
                Console.WriteLine($"[System]: {msg.Value.payload}");
                break;

            case "pubkey_response":
                var responseParts = msg.Value.payload.Split(':', 2);
                if (responseParts.Length == 2)
                {
                    var keyUser = responseParts[0];
                    var keyData = responseParts[1];

                    // Gem altid i cache automatisk
                    lock (keyCache)
                        keyCache[keyUser] = EncryptionHelper.ImportPublicKey(keyData);

                    // Læg også i køen hvis hovedtråden venter på den
                    if (!pubkeyResponses.TryAdd(msg.Value.payload))
                    {
                        // Køen er fuld eller ingen venter – det er ok
                    }
                    pubkeyResponses.TryAdd(msg.Value.payload);
                }
                break;

            case "message":
                var parts = msg.Value.payload.Split('|', 3);
                if (parts.Length != 3) break;

                var sender = parts[0];
                var ciphertext = parts[1];
                var signature = parts[2];

                try
                {
                    var plaintext = EncryptionHelper.Decrypt(ciphertext, privateKey);

                    if (keyCache.TryGetValue(sender, out var senderKey))
                    {
                        var valid = EncryptionHelper.Verify(plaintext, signature, senderKey);
                        var indicator = valid ? "[OK]" : "[UGYLDIG SIGNATUR]";
                        Console.WriteLine($"[{sender}] {indicator}: {plaintext}");
                    }
                    else
                    {
                        Console.WriteLine($"[{sender}] (signatur ikke verificeret): {plaintext}");
                    }
                }
                catch
                {
                    Console.WriteLine($"[{sender}]: kunne ikke dekryptere besked");
                }
                break;

            case "error":
                Console.WriteLine($"[Error]: {msg.Value.payload}");
                break;
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