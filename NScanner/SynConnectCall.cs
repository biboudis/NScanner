using System;
using System.Diagnostics;
using System.Net;
using SharpPcap;
using SharpPcap.Packets;
using SharpPcap.Protocols;

namespace NScanner
{
    public class SynConnectCall
    {
        private readonly int _timeout;
        private readonly PcapDevice _dev;
        private readonly IPAddress _gatewayAddr;
 
        public bool connect(IPEndPoint ipEnd, int port)
        {
            int lLen = EthernetFields_Fields.ETH_HEADER_LEN;
            //SYN packet creation
            #region Various Initializations
            ARP arper = new ARP();
            var bytes = new byte[54];
            var tcp = new TCPPacket(lLen, bytes, true) { IPVersion = IPPacket.IPVersions.IPv4 };
            #endregion

            #region Ethernet Fields
            tcp.SourceHwAddress = _dev.Interface.MacAddress;
            arper.DeviceName = _dev.Name;
            arper.LocalIP = _dev.Interface.Addresses[1].Addr.ipAddress;
            arper.LocalMAC = _dev.Interface.MacAddress;
            //MAC address of gateway is provided by arp protocol
            tcp.DestinationHwAddress = arper.Resolve(_gatewayAddr,_dev.Name);
            tcp.EthernetProtocol = EthernetPacket.EtherType.IP;
            #endregion

            #region IP Fields

            tcp.DestinationAddress = ipEnd.Address;
            tcp.SourceAddress = _dev.Interface.Addresses[1].Addr.ipAddress;
            tcp.IPProtocol = IPProtocol.IPProtocolType.TCP;
            tcp.TimeToLive = 20;
            tcp.ipv4.Id = 100;
            tcp.ipv4.IPTotalLength = bytes.Length - lLen;
            tcp.ipv4.IPHeaderLength = IPv4Fields_Fields.IP_HEADER_LEN;
            #endregion

            #region TCP Fields
            tcp.SourcePort = 2222;
            tcp.DestinationPort = port;
            tcp.Syn = true;
            tcp.WindowSize = 555;
            tcp.SequenceNumber = 0;
            tcp.TCPHeaderLength = TCPFields_Fields.TCP_HEADER_LEN;
            #endregion

            //Headers checksum calculations
            tcp.ipv4.ComputeIPChecksum();
            tcp.ComputeTCPChecksum();

            _dev.Open(false, 20);
            _dev.SetFilter("ip src " + tcp.DestinationAddress + " and tcp src port " + tcp.DestinationPort + " and tcp dst port " + tcp.SourcePort);

            //Send the packet
            Console.Write("Sending SYN packet: " + tcp + "...");
            _dev.SendPacket(tcp);
            Console.WriteLine("SYN Packet sent.");
            TCPPacket reply = null;
            var watch = new Stopwatch();
            bool received = false;
            watch.Start();
            //Condition including timeout check.
            while (watch.ElapsedMilliseconds < _timeout && received != true)
            {
                if ((reply = (TCPPacket) _dev.GetNextPacket()) != null)
                {
                    Console.WriteLine("SYN ACK Reply received: " + reply);
                    received = true;
                }
            }
            //A reply hasn't returned
            if (!received)
            {
                _dev.Close(); 
                throw new Exception("TIME_OUT");
            }            
            //Remote host reported closed connection
            if (reply.Rst)
            {
                _dev.Close(); 
                throw new Exception("CLOSED");
            }
            //Remote host reported opened connection
            if (reply.Ack)
            {
                tcp.Syn = false;
                tcp.Rst = true;
                tcp.WindowSize = 0;
                tcp.ipv4.ComputeIPChecksum();
                tcp.ComputeTCPChecksum();
                Console.Write("Sending RST packet: " + tcp + "...");
                _dev.SendPacket(tcp);
                Console.WriteLine("RST Packet sent.");
                _dev.Close(); 
            }

            return true;

        }

        public SynConnectCall(int timeout, PcapDevice dev, IPAddress addr)
        {
            _timeout = timeout;
            _dev = dev;
            _gatewayAddr = addr;
        }
    }

}