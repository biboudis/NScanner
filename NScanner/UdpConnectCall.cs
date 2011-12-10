using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NScanner
{
    public class UdpConnectCall
    {
        private readonly UdpClient _client;
        private readonly int _timeout;

        public void Connect(EndPoint endPoint)
        {
            byte[] data = new byte[1024];
            string input, stringData;
            int recv;
            Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            int sockopt = (int)server.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout);
            Console.WriteLine("Default timeout: {0}", sockopt);
            server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, _timeout);
            sockopt = (int)server.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout);
            Console.WriteLine("New timeout: {0}", sockopt);

            string welcome = "Hello, are you there?";
            data = Encoding.ASCII.GetBytes(welcome);
            server.SendTo(data, data.Length, SocketFlags.None, endPoint);

            data = new byte[1024];
            try
            {
                Console.WriteLine("Waiting from {0}:", endPoint.ToString());
                recv = server.ReceiveFrom(data, ref endPoint);
                Console.WriteLine("Message received from {0}:", endPoint.ToString());
                Console.WriteLine(Encoding.ASCII.GetString(data, 0, recv));
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.HostUnreachable)
                    throw new Exception("CLOSED");
                throw new Exception("TIME_OUT");
            }
            Console.WriteLine("Stopping client");
            server.Close();
        }          
        
        public UdpConnectCall(int timeout)
        {
            _timeout = timeout;
            _client = new UdpClient();
        }
    }
}