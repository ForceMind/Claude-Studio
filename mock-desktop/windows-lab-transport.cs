using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

// A private TCP echo target and a fixed-destination relay, all bound to loopback.
public sealed class StudioLabTransport : IDisposable
{
    private readonly TcpListener target4, target6;
    private TcpListener relay;
    private readonly UdpClient udp4, udp6;
    private readonly List<TcpClient> sockets = new List<TcpClient>();
    private readonly List<TcpClient> relaySockets = new List<TcpClient>();
    private bool forwarding = true;
    private volatile bool disposed;
    private int directSignals, udpSignals;
    public int DirectSignals { get { return Volatile.Read(ref directSignals); } }
    public int UdpSignals { get { return Volatile.Read(ref udpSignals); } }
    public int Port4 { get; private set; }
    public int Port6 { get; private set; }
    public int Udp4 { get; private set; }
    public int Udp6 { get; private set; }
    public int ProxyPort { get; private set; }

    public StudioLabTransport() {
        try {
            target4 = Create(IPAddress.Loopback, 0);
            target6 = Create(IPAddress.IPv6Loopback, 0);
            relay = Create(IPAddress.Loopback, 0);
            Port4 = Port(target4); Port6 = Port(target6); ProxyPort = Port(relay);
            if (Port4 < 49152 || Port6 < 49152 || ProxyPort < 49152) throw new InvalidOperationException("Expected ephemeral loopback ports");
            udp4 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            udp6 = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            Udp4 = ((IPEndPoint)udp4.Client.LocalEndPoint).Port;
            Udp6 = ((IPEndPoint)udp6.Client.LocalEndPoint).Port;
            if (Udp4 < 49152 || Udp6 < 49152) throw new InvalidOperationException("Expected ephemeral UDP ports");
            Accept(target4, false); Accept(target6, false); Accept(relay, true);
            EchoDatagrams(udp4); EchoDatagrams(udp6);
        } catch { Dispose(); throw; }
    }
    private static TcpListener Create(IPAddress address, int port) {
        var listener = new TcpListener(address, port);
        listener.ExclusiveAddressUse = true;
        listener.Start();
        return listener;
    }
    private static int Port(TcpListener listener) { return ((IPEndPoint)listener.LocalEndpoint).Port; }
    private async void EchoDatagrams(UdpClient udp) {
        try {
            while (!disposed) {
                var message = await udp.ReceiveAsync();
                Interlocked.Increment(ref udpSignals);
                await udp.SendAsync(message.Buffer, message.Buffer.Length, message.RemoteEndPoint);
            }
        } catch (SocketException) { } catch (ObjectDisposedException) { }
    }
    private async void Accept(TcpListener listener, bool proxy) {
        try {
            while (!disposed) {
                var client = await listener.AcceptTcpClientAsync();
                lock (sockets) {
                    if (disposed || (proxy && !forwarding)) { client.Close(); continue; }
                    sockets.Add(client);
                    if (proxy) relaySockets.Add(client);
                }
                Serve(client, proxy);
            }
        } catch (SocketException) { } catch (ObjectDisposedException) { }
    }
    private async void Serve(TcpClient client, bool proxy) {
        TcpClient upstream = null;
        try {
            if (proxy) {
                upstream = new TcpClient(AddressFamily.InterNetwork);
                lock (sockets) {
                    if (disposed || !forwarding) return;
                    relaySockets.Add(upstream);
                }
                await upstream.ConnectAsync(IPAddress.Loopback, Port4);
                var send = client.GetStream().CopyToAsync(upstream.GetStream());
                var receive = upstream.GetStream().CopyToAsync(client.GetStream());
                await await Task.WhenAny(send, receive);
            } else {
                var stream = client.GetStream();
                var data = new byte[1024];
                int length;
                while ((length = await stream.ReadAsync(data, 0, data.Length)) > 0) {
                    if (data[0] == (byte)'G') {
                        await ReplyToSyntheticHttp(stream, data, length);
                        return;
                    }
                    for (int i = 0; i < length; i++)
                        if (data[i] == 85) Interlocked.Increment(ref directSignals);
                    await stream.WriteAsync(data, 0, length);
                }
            }
        } catch (System.IO.IOException) { } catch (SocketException) { }
          catch (ObjectDisposedException) { } catch (InvalidOperationException) { }
        finally {
            lock (sockets) {
                client.Close(); sockets.Remove(client); relaySockets.Remove(client);
                if (upstream != null) { upstream.Close(); relaySockets.Remove(upstream); }
            }
        }
    }
    private static async Task ReplyToSyntheticHttp(NetworkStream stream, byte[] first, int length) {
        var ascii = System.Text.Encoding.ASCII;
        string header = ascii.GetString(first, 0, length);
        var more = new byte[1024];
        while (!header.Contains("\r\n\r\n") && header.Length < 4096) {
            int received = await stream.ReadAsync(more, 0, more.Length);
            if (received == 0) return;
            header += ascii.GetString(more, 0, received);
        }
        if (!header.Contains("\r\n\r\n") || !header.StartsWith("GET ") || !header.Contains("/studio-probe?")) return;
        byte[] response = ascii.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nstudio-probe");
        await stream.WriteAsync(response, 0, response.Length);
    }
    public void FailProxy() {
        lock (sockets) {
            forwarding = false;
            foreach (var socket in relaySockets.ToArray()) socket.Close();
        }
    }
    public void StopProxy() { FailProxy(); relay.Stop(); }
    public void ResumeProxy() {
        lock (sockets) { forwarding = true; }
        relay = Create(IPAddress.Loopback, ProxyPort);
        Accept(relay, true);
    }
    public void Dispose() {
        lock (sockets) {
            if (disposed) return;
            disposed = true;
            if (relay != null) relay.Stop();
            if (target6 != null) target6.Stop();
            if (target4 != null) target4.Stop();
            if (udp6 != null) udp6.Close();
            if (udp4 != null) udp4.Close();
            foreach (var socket in sockets.ToArray()) socket.Close();
            foreach (var socket in relaySockets.ToArray()) socket.Close();
        }
    }
}
