/*
 * ShapDHCPServer (C) 2010, Cluster
 * http://clusterrr.com
 * http://code.google.com/p/sharpdhcpserver/
 * 
 *           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *                   Version 2, December 2004
 *
 * Copyright (C) 2004 Sam Hocevar
 * 14 rue de Plaisance, 75014 Paris, France
 * Everyone is permitted to copy and distribute verbatim or modified
 * copies of this license document, and changing it is allowed as long
 * as the name is changed.
 *
 *           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *  TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 *
 * 0. You just DO WHAT THE FUCK YOU WANT TO.
 * 
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;

namespace Cluster.SharpDHCPServer
{
    /// <summary>
    /// DHCP request
    /// </summary>
    public class DHCPRequest
    {
        private readonly DHCPServer dhcpServer;
        private readonly DHCPPacket requestData;
        private Socket requestSocket;
        private const int OPTION_OFFSET = 240;
        private const int PORT_TO_SEND_TO_CLIENT = 68;
        private const int PORT_TO_SEND_TO_RELAY = 67;

        /// <summary>
        /// Raw DHCP packet
        /// </summary>
        public struct DHCPPacket
        {
            /// <summary>Op code:   1 = boot request, 2 = boot reply</summary>
            public byte op;
            /// <summary>Hardware address type</summary>
            public byte htype;
            /// <summary>Hardware address length: length of MACID</summary>
            public byte hlen;
            /// <summary>Hardware options</summary>
            public byte hops;
            /// <summary>Transaction id</summary>
            public byte[] xid;
            /// <summary>Elapsed time from trying to boot</summary>
            public byte[] secs;
            /// <summary>Flags</summary>
            public byte[] flags;
            /// <summary>Client IP</summary>
            public byte[] ciaddr;
            /// <summary>Your client IP</summary>
            public byte[] yiaddr;
            /// <summary>Server IP</summary>
            public byte[] siaddr;
            /// <summary>Relay agent IP</summary>
            public byte[] giaddr;
            /// <summary>Client HW address</summary>
            public byte[] chaddr;
            /// <summary>Optional server host name</summary>
            public byte[] sname;
            /// <summary>Boot file name</summary>
            public byte[] file;
            /// <summary>Magic cookie</summary>
            public byte[] mcookie;
            /// <summary>Options (rest)</summary>
            public byte[] options;
        }

        internal DHCPRequest(byte[] data, Socket socket, DHCPServer server)
        {
            dhcpServer = server;
            System.IO.BinaryReader rdr;
            System.IO.MemoryStream stm = new System.IO.MemoryStream(data, 0, data.Length);
            rdr = new System.IO.BinaryReader(stm);
            // Reading data
            requestData.op = rdr.ReadByte();
            requestData.htype = rdr.ReadByte();
            requestData.hlen = rdr.ReadByte();
            requestData.hops = rdr.ReadByte();
            requestData.xid = rdr.ReadBytes(4);
            requestData.secs = rdr.ReadBytes(2);
            requestData.flags = rdr.ReadBytes(2);
            requestData.ciaddr = rdr.ReadBytes(4);
            requestData.yiaddr = rdr.ReadBytes(4);
            requestData.siaddr = rdr.ReadBytes(4);
            requestData.giaddr = rdr.ReadBytes(4);
            requestData.chaddr = rdr.ReadBytes(16);
            requestData.sname = rdr.ReadBytes(64);
            requestData.file = rdr.ReadBytes(128);
            requestData.mcookie = rdr.ReadBytes(4);
            requestData.options = rdr.ReadBytes(data.Length - OPTION_OFFSET);
            requestSocket = socket;
        }

        /// <summary>
        /// Returns array of requested by client options
        /// </summary>
        /// <returns>Array of requested by client options</returns>
        public DHCPOption[] GetRequestedOptionsList()
        {
            var reqList = this.GetOptionData(DHCPOption.ParameterRequestList);
            var optList = new List<DHCPOption>();
            if (reqList != null) foreach (var option in reqList) optList.Add((DHCPOption)option); else return null;
            return optList.ToArray();
        }

        private byte[] CreateOptionStruct(DHCPMsgType msgType, DHCPReplyOptions replyOptions, Dictionary<DHCPOption, byte[]> otherForceOptions)
        {
            byte[] resultOptions = null;
            // Requested options
            var reqList = GetRequestedOptionsList();
            // Option82?
            var relayInfo = this.GetOptionData(DHCPOption.RelayInfo);
            CreateOptionElement(ref resultOptions, DHCPOption.DHCPMessageTYPE, new byte[] { (byte)msgType });
            // Server identifier - our IP address
            if ((replyOptions != null) && (replyOptions.ServerIdentifier != null))
                CreateOptionElement(ref resultOptions, DHCPOption.ServerIdentifier, replyOptions.ServerIdentifier.GetAddressBytes());

            // Requested options
            if ((reqList != null) && (replyOptions != null))
                foreach (DHCPOption i in reqList)
                {
                    byte[] optionData = null;
                    // If it's force option - ignore it. We'll send it later.
                    if ((otherForceOptions != null) && (otherForceOptions.TryGetValue(i, out optionData)))
                        continue;
                    switch (i)
                    {
                        case DHCPOption.SubnetMask:
                            if (replyOptions.SubnetMask != null)
                                optionData = replyOptions.SubnetMask.GetAddressBytes();
                            break;
                        case DHCPOption.Router:
                            if (replyOptions.RouterIP != null)
                                optionData = replyOptions.RouterIP.GetAddressBytes();
                            break;
                        case DHCPOption.DomainNameServers:
                            if (replyOptions.DomainNameServers != null)
                            {
                                optionData = new byte[] { };
                                foreach (var dns in replyOptions.DomainNameServers)
                                {
                                    var dnsserv = dns.GetAddressBytes();
                                    Array.Resize(ref optionData, optionData.Length + 4);
                                    Array.Copy(dnsserv, 0, optionData, optionData.Length - 4, 4);
                                }
                            }
                            break;
                        case DHCPOption.DomainName:
                            if (!string.IsNullOrEmpty(replyOptions.DomainName))
                                optionData = System.Text.Encoding.ASCII.GetBytes(replyOptions.DomainName);
                            break;
                        case DHCPOption.ServerIdentifier:
                            if (replyOptions.ServerIdentifier != null)
                                optionData = replyOptions.ServerIdentifier.GetAddressBytes();
                            break;
                        case DHCPOption.LogServer:
                            if (replyOptions.LogServerIP != null)
                                optionData = replyOptions.LogServerIP.GetAddressBytes();
                            break;
                        case DHCPOption.StaticRoutes:
                        case DHCPOption.StaticRoutesWin:
                            if (replyOptions.StaticRoutes != null)
                            {
                                optionData = new byte[] { };
                                foreach (var route in replyOptions.StaticRoutes)
                                {
                                    var routeData = route.BuildRouteData();
                                    Array.Resize(ref optionData, optionData.Length + routeData.Length);
                                    Array.Copy(routeData, 0, optionData, optionData.Length - routeData.Length, routeData.Length);
                                }
                            }
                            break;
                        default:
                            replyOptions.OtherRequestedOptions.TryGetValue(i, out optionData);
                            break;
                    }
                    if (optionData != null)
                        CreateOptionElement(ref resultOptions, i, optionData);
                }

            if (GetMsgType() != DHCPMsgType.DHCPINFORM)
            {
                // Lease time
                if (replyOptions != null)
                {
                    var leaseTime = new byte[4];
                    leaseTime[3] = (byte)(replyOptions.IPAddressLeaseTime);
                    leaseTime[2] = (byte)(replyOptions.IPAddressLeaseTime >> 8);
                    leaseTime[1] = (byte)(replyOptions.IPAddressLeaseTime >> 16);
                    leaseTime[0] = (byte)(replyOptions.IPAddressLeaseTime >> 24);
                    CreateOptionElement(ref resultOptions, DHCPOption.IPAddressLeaseTime, leaseTime);
                    leaseTime[3] = (byte)(replyOptions.RenewalTimeValue_T1);
                    leaseTime[2] = (byte)(replyOptions.RenewalTimeValue_T1 >> 8);
                    leaseTime[1] = (byte)(replyOptions.RenewalTimeValue_T1 >> 16);
                    leaseTime[0] = (byte)(replyOptions.RenewalTimeValue_T1 >> 24);
                    CreateOptionElement(ref resultOptions, DHCPOption.RenewalTimeValue_T1, leaseTime);
                    leaseTime[3] = (byte)(replyOptions.RebindingTimeValue_T2);
                    leaseTime[2] = (byte)(replyOptions.RebindingTimeValue_T2 >> 8);
                    leaseTime[1] = (byte)(replyOptions.RebindingTimeValue_T2 >> 16);
                    leaseTime[0] = (byte)(replyOptions.RebindingTimeValue_T2 >> 24);
                    CreateOptionElement(ref resultOptions, DHCPOption.RebindingTimeValue_T2, leaseTime);
                }
            }
            // Other requested options
            if (otherForceOptions != null)
                foreach (var option in otherForceOptions.Keys)
                {
                    CreateOptionElement(ref resultOptions, option, otherForceOptions[option]);
                    if (option == DHCPOption.RelayInfo) relayInfo = null;
                }

            // Option 82? Send it back!
            if (relayInfo != null)
                CreateOptionElement(ref resultOptions, DHCPOption.RelayInfo, relayInfo);

            // Create the end option
            Array.Resize(ref resultOptions, resultOptions.Length + 1);
            Array.Copy(new byte[] { 255 }, 0, resultOptions, resultOptions.Length - 1, 1);
            return resultOptions;
        }

        static private void CreateOptionElement(ref byte[] options, DHCPOption option, byte[] data)
        {
            byte[] optionData;

            optionData = new byte[data.Length + 2];
            optionData[0] = (byte)option;
            optionData[1] = (byte)data.Length;
            Array.Copy(data, 0, optionData, 2, data.Length);
            if (options == null)
                Array.Resize(ref options, (int)optionData.Length);
            else
                Array.Resize(ref options, options.Length + optionData.Length);
            Array.Copy(optionData, 0, options, options.Length - optionData.Length, optionData.Length);
        }

        /// <summary>
        /// Sends DHCP reply
        /// </summary>
        /// <param name="msgType">Type of DHCP message to send</param>
        /// <param name="ip">IP for client</param>
        /// <param name="replyData">Reply options (will be sent if requested)</param>
        public void SendDHCPReply(DHCPMsgType msgType, IPAddress ip, DHCPReplyOptions replyData)
        {
            SendDHCPReply(msgType, ip, replyData, null);
        }
        /// <summary>
        /// Sends DHCP reply
        /// </summary>
        /// <param name="msgType">Type of DHCP message to send</param>
        /// <param name="ip">IP for client</param>
        /// <param name="replyData">Reply options (will be sent if requested)</param>
        /// <param name="otherForceOptions">Force reply options (will be sent anyway)</param>
        public void SendDHCPReply(DHCPMsgType msgType, IPAddress ip, DHCPReplyOptions replyData, Dictionary<DHCPOption, byte[]> otherForceOptions)
        {
            var replyBuffer = requestData;
            replyBuffer.op = 2; // Reply
            replyBuffer.yiaddr = ip.GetAddressBytes(); // Client's IP
            replyBuffer.options = CreateOptionStruct(msgType, replyData, otherForceOptions); // Options
            if (!string.IsNullOrEmpty(dhcpServer.ServerName))
            {
                var serverNameBytes = Encoding.ASCII.GetBytes(dhcpServer.ServerName);
                int len = (serverNameBytes.Length > 63) ? 63 : serverNameBytes.Length;
                Array.Copy(serverNameBytes, replyBuffer.sname, len);
                replyBuffer.sname[len] = 0;
            }
            lock (requestSocket)
            {
                IPEndPoint endPoint;
                if ((replyBuffer.giaddr[0] == 0) && (replyBuffer.giaddr[1] == 0) &&
                    (replyBuffer.giaddr[2] == 0) && (replyBuffer.giaddr[3] == 0))
                {
                    requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                    endPoint = new IPEndPoint(IPAddress.Broadcast, PORT_TO_SEND_TO_CLIENT);
                }
                else
                {
                    requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, false);
                    endPoint = new IPEndPoint(new IPAddress(replyBuffer.giaddr), PORT_TO_SEND_TO_RELAY);
                }
                var DataToSend = BuildDataStructure(replyBuffer);
                requestSocket.SendTo(DataToSend, endPoint);
            }
        }

        private static byte[] BuildDataStructure(DHCPPacket packet)
        {
            byte[] mArray;

            try
            {
                mArray = new byte[0];
                AddOptionElement(new byte[] { packet.op }, ref mArray);
                AddOptionElement(new byte[] { packet.htype }, ref mArray);
                AddOptionElement(new byte[] { packet.hlen }, ref mArray);
                AddOptionElement(new byte[] { packet.hops }, ref mArray);
                AddOptionElement(packet.xid, ref mArray);
                AddOptionElement(packet.secs, ref mArray);
                AddOptionElement(packet.flags, ref mArray);
                AddOptionElement(packet.ciaddr, ref mArray);
                AddOptionElement(packet.yiaddr, ref mArray);
                AddOptionElement(packet.siaddr, ref mArray);
                AddOptionElement(packet.giaddr, ref mArray);
                AddOptionElement(packet.chaddr, ref mArray);
                AddOptionElement(packet.sname, ref mArray);
                AddOptionElement(packet.file, ref mArray);

                AddOptionElement(packet.mcookie, ref mArray);
                AddOptionElement(packet.options, ref mArray);
                return mArray;
            }
            finally
            {
                mArray = null;
            }
        }

        private static void AddOptionElement(byte[] fromValue, ref byte[] targetArray)
        {
            if (targetArray != null)
                Array.Resize(ref targetArray, targetArray.Length + fromValue.Length);
            else
                Array.Resize(ref targetArray, fromValue.Length);
            Array.Copy(fromValue, 0, targetArray, targetArray.Length - fromValue.Length, fromValue.Length);
        }

        /// <summary>
        /// Returns option content
        /// </summary>
        /// <param name="option">Option to retrieve</param>
        /// <returns>Option content</returns>
        public byte[] GetOptionData(DHCPOption option)
        {
            int DHCPId = 0;
            byte DDataID, DataLength = 0;
            byte[] dumpData;

            DHCPId = (int)option;
            for (int i = 0; i < requestData.options.Length; i++)
            {
                DDataID = requestData.options[i];
                if (DDataID == (byte)DHCPOption.END_Option) break;
                if (DDataID == DHCPId)
                {
                    DataLength = requestData.options[i + 1];
                    dumpData = new byte[DataLength];
                    Array.Copy(requestData.options, i + 2, dumpData, 0, DataLength);
                    return dumpData;
                }
                else
                {
                    DataLength = requestData.options[i + 1];
                    i += 1 + DataLength;
                }
            }

            return null;
        }

        /// <summary>
        /// Returns all options
        /// </summary>
        /// <returns>Options dictionary</returns>
        public Dictionary<DHCPOption, byte[]> GetAllOptions()
        {
            var result = new Dictionary<DHCPOption, byte[]>();
            DHCPOption DDataID;
            byte DataLength = 0;

            for (int i = 0; i < requestData.options.Length; i++)
            {
                DDataID = (DHCPOption)requestData.options[i];
                if (DDataID == DHCPOption.END_Option) break;
                DataLength = requestData.options[i + 1];
                byte[] dumpData = new byte[DataLength];
                Array.Copy(requestData.options, i + 2, dumpData, 0, DataLength);
                result[DDataID] = dumpData;

                DataLength = requestData.options[i + 1];
                i += 1 + DataLength;
            }

            return result;
        }

        /// <summary>
        /// Returns ciaddr (client IP address)
        /// </summary>
        /// <returns>ciaddr</returns>
        public IPAddress GetCiaddr()
        {
            if ((requestData.ciaddr[0] == 0) &&
                (requestData.ciaddr[1] == 0) &&
                (requestData.ciaddr[2] == 0) &&
                (requestData.ciaddr[3] == 0)
                ) return null;
            return new IPAddress(requestData.ciaddr);
        }
        /// <summary>
        /// Returns giaddr (gateway IP address switched by relay)
        /// </summary>
        /// <returns>giaddr</returns>
        public IPAddress GetGiaddr()
        {
            if ((requestData.giaddr[0] == 0) &&
                (requestData.giaddr[1] == 0) &&
                (requestData.giaddr[2] == 0) &&
                (requestData.giaddr[3] == 0)
                ) return null;
            return new IPAddress(requestData.giaddr);
        }
        /// <summary>
        /// Returns chaddr (client hardware address)
        /// </summary>
        /// <returns>chaddr</returns>
        public byte[] GetChaddr()
        {
            var res = new byte[requestData.hlen];
            Array.Copy(requestData.chaddr, res, requestData.hlen);
            return res;
        }
        /// <summary>
        /// Returns requested IP (option 50)
        /// </summary>
        /// <returns>Requested IP</returns>
        public IPAddress GetRequestedIP()
        {
            var ipBytes = GetOptionData(DHCPOption.RequestedIPAddress);
            if (ipBytes == null) return null;
            return new IPAddress(ipBytes);
        }
        /// <summary>
        /// Returns type of DHCP request
        /// </summary>
        /// <returns>DHCP message type</returns>
        public DHCPMsgType GetMsgType()
        {
            byte[] DData;
            DData = GetOptionData(DHCPOption.DHCPMessageTYPE);
            if (DData != null)
                return (DHCPMsgType)DData[0];
            return 0;
        }
        /// <summary>
        /// Returns entire content of DHCP packet
        /// </summary>
        /// <returns>DHCP packet</returns>
        public DHCPPacket GetRawPacket()
        {
            return requestData;
        }
        /// <summary>
        /// Returns relay info (option 82)
        /// </summary>
        /// <returns>Relay info</returns>
        public RelayInfo? GetRelayInfo()
        {
            var result = new RelayInfo();
            var relayInfo = GetOptionData(DHCPOption.RelayInfo);
            if (relayInfo != null)
            {
                int i = 0;
                while (i < relayInfo.Length)
                {
                    var subOptID = relayInfo[i];
                    if (subOptID == 1)
                    {
                        result.AgentCircuitID = new byte[relayInfo[i + 1]];
                        Array.Copy(relayInfo, i + 2, result.AgentCircuitID, 0, relayInfo[i + 1]);
                    }
                    else if (subOptID == 2)
                    {
                        result.AgentRemoteID = new byte[relayInfo[i + 1]];
                        Array.Copy(relayInfo, i + 2, result.AgentRemoteID, 0, relayInfo[i + 1]);
                    }
                    i += 2 + relayInfo[i + 1];
                }
                return result;
            }
            return null;            
        }
    }

    /// <summary>
    /// DHCP Server
    /// </summary>
    public class DHCPServer : IDisposable
    {
        /// <summary>Delegate for DHCP message</summary>
        public delegate void DHCPDataReceivedEventHandler(DHCPRequest dhcpRequest);

        /// <summary>Will be called on any DHCP message</summary>
        public event DHCPDataReceivedEventHandler OnDataReceived = delegate { };
        /// <summary>Will be called on any DISCOVER message</summary>
        public event DHCPDataReceivedEventHandler OnDiscover = delegate { };
        /// <summary>Will be called on any REQUEST message</summary>
        public event DHCPDataReceivedEventHandler OnRequest = delegate { };
        /// <summary>Will be called on any DECLINE message</summary>
        public event DHCPDataReceivedEventHandler OnDecline = delegate { };
        /// <summary>Will be called on any DECLINE released</summary>
        public event DHCPDataReceivedEventHandler OnReleased = delegate { };
        /// <summary>Will be called on any DECLINE inform</summary>
        public event DHCPDataReceivedEventHandler OnInform = delegate { };

        /// <summary>Server name (optional)</summary>
        public string ServerName { get; set; }

        private Socket socket = null;
        private Thread receiveDataThread = null;
        private const int PORT_TO_LISTEN_TO = 67;

        /// <summary>
        /// Creates DHCP server, it will be started instantly
        /// </summary>
        /// <param name="bindIp">IP address to bind</param>
        public DHCPServer(IPAddress bindIp)
        {
            var ipLocalEndPoint = new IPEndPoint(bindIp, PORT_TO_LISTEN_TO);
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(ipLocalEndPoint);
            receiveDataThread = new Thread(ReceiveDataThread);
            receiveDataThread.Start();
        }

        /// <summary>Creates DHCP server, it will be started instantly</summary>
        public DHCPServer() : this(IPAddress.Any)
        {
        }

        /// <summary>Disposes DHCP server</summary>
        public void Dispose()
        {
            if (socket != null)
            {
                socket.Close();
                socket = null;
            }
            if (receiveDataThread != null)
            {
                receiveDataThread.Abort();
                receiveDataThread = null;
            }
        }

        private void ReceiveDataThread()
        {
            while (true)
            {
                try
                {
                    IPEndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                    EndPoint remote = (EndPoint)(sender); var buffer = new byte[1024];
                    int len = socket.ReceiveFrom(buffer, ref remote);
                    if (len > 0)
                    {
                        Array.Resize(ref buffer, len);
                        var dataReceivedThread = new Thread(DataReceived);
                        dataReceivedThread.Start(buffer);
                    }
                }
                catch
                {
                    // Ignore all
                }
            }
        }

        private void DataReceived(object o)
        {
            var data = (byte[])o;
            try
            {
                var dhcpRequest = new DHCPRequest(data, socket, this);
                //ccDHCP = new clsDHCP();


                //data is now in the structure
                //get the msg type
                OnDataReceived(dhcpRequest);
                var msgType = dhcpRequest.GetMsgType();
                switch (msgType)
                {
                    case DHCPMsgType.DHCPDISCOVER:
                        OnDiscover(dhcpRequest);
                        break;
                    case DHCPMsgType.DHCPREQUEST:
                        OnRequest(dhcpRequest);
                        break;
                    case DHCPMsgType.DHCPDECLINE:
                        OnDecline(dhcpRequest);
                        break;
                    case DHCPMsgType.DHCPRELEASE:
                        OnReleased(dhcpRequest);
                        break;
                    case DHCPMsgType.DHCPINFORM:
                        OnInform(dhcpRequest);
                        break;
                    //default:
                    //    Console.WriteLine("Unknown DHCP message: " + (int)MsgTyp + " (" + MsgTyp.ToString() + ")");
                    //    break;
                }
            }
            catch
            {
                // Ignore
            }
        }
    }

    /// <summary>DHCP message type</summary>
    public enum DHCPMsgType
    {
        /// <summary>DHCP DISCOVER message</summary>
        DHCPDISCOVER = 1,
        /// <summary>DHCP OFFER message</summary>
        DHCPOFFER = 2,
        /// <summary>DHCP REQUEST message</summary>
        DHCPREQUEST = 3,
        /// <summary>DHCP DECLINE message</summary>
        DHCPDECLINE = 4,
        /// <summary>DHCP ACK message</summary>
        DHCPACK = 5,
        /// <summary>DHCP NAK message</summary>
        DHCPNAK = 6,
        /// <summary>DHCP RELEASE message</summary>
        DHCPRELEASE = 7,
        /// <summary>DHCP INFORM message</summary>
        DHCPINFORM = 8
    }

    /// <summary>DHCP option enum</summary>
    public enum DHCPOption
    {
        /// <summary>Option 1</summary>
        SubnetMask = 1,
        /// <summary>Option 2</summary>
        TimeOffset = 2,
        /// <summary>Option 3</summary>
        Router = 3,
        /// <summary>Option 4</summary>
        TimeServer = 4,
        /// <summary>Option 5</summary>
        NameServer = 5,
        /// <summary>Option 6</summary>
        DomainNameServers = 6,
        /// <summary>Option 7</summary>
        LogServer = 7,
        /// <summary>Option 8</summary>
        CookieServer = 8,
        /// <summary>Option 9</summary>
        LPRServer = 9,
        /// <summary>Option 10</summary>
        ImpressServer = 10,
        /// <summary>Option 11</summary>
        ResourceLocServer = 11,
        /// <summary>Option 12</summary>
        HostName = 12,
        /// <summary>Option 13</summary>
        BootFileSize = 13,
        /// <summary>Option 14</summary>
        MeritDump = 14,
        /// <summary>Option 15</summary>
        DomainName = 15,
        /// <summary>Option 16</summary>
        SwapServer = 16,
        /// <summary>Option 17</summary>
        RootPath = 17,
        /// <summary>Option 18</summary>
        ExtensionsPath = 18,
        /// <summary>Option 19</summary>
        IpForwarding = 19,
        /// <summary>Option 20</summary>
        NonLocalSourceRouting = 20,
        /// <summary>Option 21</summary>
        PolicyFilter = 21,
        /// <summary>Option 22</summary>
        MaximumDatagramReAssemblySize = 22,
        /// <summary>Option 23</summary>
        DefaultIPTimeToLive = 23,
        /// <summary>Option 24</summary>
        PathMTUAgingTimeout = 24,
        /// <summary>Option 25</summary>
        PathMTUPlateauTable = 25,
        /// <summary>Option 26</summary>
        InterfaceMTU = 26,
        /// <summary>Option 27</summary>
        AllSubnetsAreLocal = 27,
        /// <summary>Option 28</summary>
        BroadcastAddress = 28,
        /// <summary>Option 29</summary>
        PerformMaskDiscovery = 29,
        /// <summary>Option 30</summary>
        MaskSupplier = 30,
        /// <summary>Option 31</summary>
        PerformRouterDiscovery = 31,
        /// <summary>Option 32</summary>
        RouterSolicitationAddress = 32,
        /// <summary>Option 33</summary>
        StaticRoute = 33,
        /// <summary>Option 34</summary>
        TrailerEncapsulation = 34,
        /// <summary>Option 35</summary>
        ARPCacheTimeout = 35,
        /// <summary>Option 36</summary>
        EthernetEncapsulation = 36,
        /// <summary>Option 37</summary>
        TCPDefaultTTL = 37,
        /// <summary>Option 38</summary>
        TCPKeepaliveInterval = 38,
        /// <summary>Option 39</summary>
        TCPKeepaliveGarbage = 39,
        /// <summary>Option 40</summary>
        NetworkInformationServiceDomain = 40,
        /// <summary>Option 41</summary>
        NetworkInformationServers = 41,
        /// <summary>Option 42</summary>
        NetworkTimeProtocolServers = 42,
        /// <summary>Option 43</summary>
        VendorSpecificInformation = 43,
        /// <summary>Option 44</summary>
        NetBIOSoverTCPIPNameServer = 44,
        /// <summary>Option 45</summary>
        NetBIOSoverTCPIPDatagramDistributionServer = 45,
        /// <summary>Option 46</summary>
        NetBIOSoverTCPIPNodeType = 46,
        /// <summary>Option 47</summary>
        NetBIOSoverTCPIPScope = 47,
        /// <summary>Option 48</summary>
        XWindowSystemFontServer = 48,
        /// <summary>Option 49</summary>
        XWindowSystemDisplayManager = 49,
        /// <summary>Option 50</summary>
        RequestedIPAddress = 50,
        /// <summary>Option 51</summary>
        IPAddressLeaseTime = 51,
        /// <summary>Option 52</summary>
        OptionOverload = 52,
        /// <summary>Option 53</summary>
        DHCPMessageTYPE = 53,
        /// <summary>Option 54</summary>
        ServerIdentifier = 54,
        /// <summary>Option 55</summary>
        ParameterRequestList = 55,
        /// <summary>Option 56</summary>
        Message = 56,
        /// <summary>Option 57</summary>
        MaximumDHCPMessageSize = 57,
        /// <summary>Option 58</summary>
        RenewalTimeValue_T1 = 58,
        /// <summary>Option 59</summary>
        RebindingTimeValue_T2 = 59,
        /// <summary>Option 60</summary>
        Vendorclassidentifier = 60,
        /// <summary>Option 61</summary>
        ClientIdentifier = 61,
        /// <summary>Option 62</summary>
        NetWateIPDomainName = 62,
        /// <summary>Option 63</summary>
        NetWateIPInformation = 63,
        /// <summary>Option 64</summary>
        NetworkInformationServicePlusDomain = 64,
        /// <summary>Option 65</summary>
        NetworkInformationServicePlusServers = 65,
        /// <summary>Option 66</summary>
        TFTPServerName = 66,
        /// <summary>Option 67</summary>
        BootfileName = 67,
        /// <summary>Option 68</summary>
        MobileIPHomeAgent = 68,
        /// <summary>Option 69</summary>
        SMTPServer = 69,
        /// <summary>Option 70</summary>
        POP3Server = 70,
        /// <summary>Option 71</summary>
        NNTPServer = 71,
        /// <summary>Option 72</summary>
        DefaultWWWServer = 72,
        /// <summary>Option 73</summary>
        DefaultFingerServer = 73,
        /// <summary>Option 74</summary>
        DefaultIRCServer = 74,
        /// <summary>Option 75</summary>
        StreetTalkServer = 75,
        /// <summary>Option 76</summary>
        STDAServer = 76,
        /// <summary>Option 82</summary>
        RelayInfo = 82,
        /// <summary>Option 121</summary>
        StaticRoutes = 121,
        /// <summary>Option 249</summary>
        StaticRoutesWin = 249,
        /// <summary>Option 255 (END option)</summary>
        END_Option = 255
    }

    /// <summary>Reply options</summary>
    public class DHCPReplyOptions
    {
        /// <summary>IP address</summary>
        public IPAddress SubnetMask = null;
        /// <summary>IP address lease time (seconds)</summary>
        public UInt32 IPAddressLeaseTime = 60 * 60 * 24;
        /// <summary>Renewal time (seconds)</summary>
        public UInt32 RenewalTimeValue_T1 = 60 * 60 * 24;
        /// <summary>Rebinding time (seconds)</summary>
        public UInt32 RebindingTimeValue_T2 = 60 * 60 * 24;
        /// <summary>Domain name</summary>
        public string DomainName = null;
        /// <summary>IP address of DHCP server</summary>
        public IPAddress ServerIdentifier = null;
        /// <summary>Router (gateway) IP</summary>
        public IPAddress RouterIP = null;
        /// <summary>Domain name servers (DNS)</summary>
        public IPAddress[] DomainNameServers = null;
        /// <summary>Log server IP</summary>
        public IPAddress LogServerIP = null;
        /// <summary>Static routes</summary>
        public NetworkRoute[] StaticRoutes = null;
        /// <summary>Other options which will be sent on request</summary>
        public Dictionary<DHCPOption, byte[]> OtherRequestedOptions = new Dictionary<DHCPOption, byte[]>();
    }

    /// <summary>Network route</summary>
    public struct NetworkRoute
    {
        /// <summary>IP address of destination network</summary>
        public IPAddress Network;
        /// <summary>Subnet mask length</summary>
        public byte NetMaskLength;
        /// <summary>Gateway</summary>
        public IPAddress Gateway;

        /// <summary>Creates network route</summary>
        /// <param name="network">IP address to bind</param>
        /// <param name="netMaskLength">Subnet mask length</param>
        /// <param name="gateway">Gateway</param>
        public NetworkRoute(IPAddress network, byte netMaskLength, IPAddress gateway)
        {
            Network = network;
            NetMaskLength = netMaskLength;
            Gateway = gateway;
        }

        /// <summary>Creates network route</summary>
        /// <param name="network">IP address to bind</param>
        /// <param name="netMask">Subnet mask</param>
        /// <param name="gateway">Gateway</param>
        public NetworkRoute(IPAddress network, IPAddress netMask, IPAddress gateway)
        {
            byte length = 0;
            var mask = netMask.GetAddressBytes();
            for (byte x = 0; x < 4; x++)
            {
                for (byte b = 0; b < 8; b++)
                    if (((mask[x] >> (7 - b)) & 1) == 1)
                        length++;
                    else break;
            }
            Network = network;
            NetMaskLength = length;
            Gateway = gateway;
        }

        internal byte[] BuildRouteData()
        {
            int ipLength;
            if (NetMaskLength <= 8) ipLength = 1;
            else if (NetMaskLength <= 16) ipLength = 2;
            else if (NetMaskLength <= 24) ipLength = 3;
            else ipLength = 4;
            var res = new byte[1 + ipLength + 4];
            res[0] = NetMaskLength;
            Array.Copy(Network.GetAddressBytes(), 0, res, 1, ipLength);
            Array.Copy(Gateway.GetAddressBytes(), 0, res, 1 + ipLength, 4);
            return res;
        }
    }

    /// <summary>DHCP relay information (option 82)</summary>
    public struct RelayInfo
    {
        /// <summary>Agent circuit ID</summary>
        public byte[] AgentCircuitID;
        /// <summary>Agent remote ID</summary>
        public byte[] AgentRemoteID;
    }
}
