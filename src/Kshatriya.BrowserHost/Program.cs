using Kshatriya.BrowserHost;
using Kshatriya.Runtime.Ipc;

// Native-messaging host for the Kshatriya browser extension (ADR 0018). The browser starts it for one
// request (chrome.runtime.sendNativeMessage), writes the request to stdin and reads the reply from stdout.
// Anything malformed ends the process; the browser then reports a disconnected host to the extension.
using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

await using Stream input = Console.OpenStandardInput();
await using Stream output = Console.OpenStandardOutput();

(byte[]? request, FrameError error) = await NativeFraming.ReadAsync(input, NativeFraming.MaxRequestBytes, cancel.Token);
if (request is null)
{
    return error == FrameError.None ? 0 : 2;
}

var handler = new HostHandler(
    new ServiceHostAdapter(ServiceEndpoint.Production),
    path => File.Exists(path) && !Directory.Exists(path));
byte[] reply = await handler.HandleAsync(request, cancel.Token);
await NativeFraming.WriteAsync(output, reply, cancel.Token);
return 0;
