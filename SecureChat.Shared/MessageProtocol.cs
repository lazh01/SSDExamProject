using System.Text;
using System.Text.Json;

public static class MessageProtocol
{
    public static byte[]? SharedKey { get; set; }


    public static async Task SendMessageAsync(Stream stream, string type, string payload)
    {
        var msg = JsonSerializer.Serialize(new { type, payload });
        var data = Encoding.UTF8.GetBytes(msg + "\n");
        await stream.WriteAsync(data);
    }

    public static async Task<(string type, string payload)?> ReadMessageAsync(Stream stream)
    {
        var sb = new StringBuilder();
        var singleByte = new byte[1];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(singleByte);
            if (bytesRead == 0) return null;

            char c = (char)singleByte[0];
            if (c == '\n') break;
            sb.Append(c);
        }

        var raw = sb.ToString().Trim();
        if (string.IsNullOrEmpty(raw)) return null;

        var doc = JsonDocument.Parse(raw);
        var type = doc.RootElement.GetProperty("type").GetString()!;
        var payload = doc.RootElement.GetProperty("payload").GetString()!;
        return (type, payload);
    }
}