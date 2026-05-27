using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var cert = CertHelper.GetOrCreateCertificate("server.pfx", "supersecret123");
var clients = new List<SslStream>();
var listener = new TcpListener(IPAddress.Any, 9000);
listener.Start();
Console.WriteLine("Server listening on port 9000 (TLS)...");

while (true)
{
    var tcpClient = await listener.AcceptTcpClientAsync();
    Console.WriteLine($"Client connected: {tcpClient.Client.RemoteEndPoint}");
    _ = HandleClientAsync(tcpClient, cert, clients);
}

static async Task HandleClientAsync(TcpClient tcpClient, X509Certificate2 cert, List<SslStream> clients)
{
    var sslStream = new SslStream(tcpClient.GetStream(), false);

    try
    {
        await sslStream.AuthenticateAsServerAsync(cert,
            clientCertificateRequired: false,
            checkCertificateRevocation: false);

        Console.WriteLine($"TLS handshake OK. Protocol: {sslStream.SslProtocol}");

        lock (clients) clients.Add(sslStream);

        var buffer = new byte[4096];
        while (true)
        {
            int bytesRead = await sslStream.ReadAsync(buffer);
            if (bytesRead == 0) break;

            string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine($"Received: {message}");

            List<SslStream> snapshot;
            lock (clients) snapshot = clients.Where(c => c != sslStream).ToList();

            foreach (var other in snapshot)
            {
                try
                {
                    await other.WriteAsync(Encoding.UTF8.GetBytes(message));
                }
                catch { /* klient disconnectede */ }
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Client disconnected: {ex.Message}");
    }
    finally
    {
        lock (clients) clients.Remove(sslStream);
        sslStream.Dispose();
        tcpClient.Dispose();
    }
}