using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace PasswordManagerClientDLL
{
    /// <summary>
    /// Represents a communication protocol client that communicates with a server using either plain TCP or SSL/TLS
    /// </summary>
    public class Client
    {
        /// <summary>
        /// The IP address of the server.
        /// </summary>
        private IPAddress serverIP;

        /// <summary>
        /// The endpoint of the server including IP address and port.
        /// </summary>
        private IPEndPoint serverEndPoint;

        /// <summary>
        /// The receive timeout duration in milliseconds.
        /// </summary>
        private int receiveTimeout;

        /// <summary>
        /// Indicates whether to use SSL/TLS for communication.
        /// </summary>
        private bool withSSL;

        /// <summary>
        /// Initializes a new instance of the <see cref="Client"/> class with the specified server IP, port, receive timeout, and SSL usage.
        /// </summary>
        /// <param name="serverIP">The IP address of the server.</param>
        /// <param name="serverPort">The port number of the server.</param>
        /// <param name="receiveTimeout">The receive timeout in milliseconds.</param>
        /// <param name="withSSL">A value indicating whether to use SSL/TLS for communication.</param>
        public Client(IPAddress serverIP, int serverPort, int receiveTimeout, bool withSSL)
        {
            this.serverIP = serverIP;
            this.serverEndPoint = new IPEndPoint(serverIP, serverPort);
            this.receiveTimeout = receiveTimeout;
            this.withSSL = withSSL;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Client"/> class with the specified server IP and port.
        /// Uses default values for receive timeout (120000 ms) and SSL usage (true).
        /// </summary>
        /// <param name="serverIP">The IP address of the server.</param>
        /// <param name="serverPort">The port number of the server.</param>
        public Client(IPAddress serverIP, int serverPort) : this(serverIP, serverPort, 120000, true)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Client"/> class with the specified server IP, port, and SSL usage.
        /// Uses a default value for receive timeout (120000 ms).
        /// </summary>
        /// <param name="serverIP">The IP address of the server.</param>
        /// <param name="serverPort">The port number of the server.</param>
        /// <param name="withSSL">A value indicating whether to use SSL/TLS for communication.</param>
        public Client(IPAddress serverIP, int serverPort, bool withSSL) : this(serverIP, serverPort, 120000, withSSL)
        {

        }

        /// <summary>
        /// Sends a request to the server and receives a response.
        /// </summary>
        /// <param name="method">The method to be used in the request.</param>
        /// <param name="body">The body of the request as a byte array.</param>
        /// <param name="session">The session token for the request.</param>
        /// <param name="contentType">The content type of the request body.</param>
        /// <returns>The <see cref="CommunicationProtocol"/> object received from the server.</returns>
        public CommunicationProtocol SendAndReceive(string method, byte[] body, string session, string contentType)
        {
            if (withSSL)
            {
                return SendAndReceiveSSL(method, body, session, contentType);
            }

            //create and connect socket
            Socket client = new Socket(serverIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.ReceiveTimeout = receiveTimeout;
            client.Connect(serverEndPoint);

            //req
            string reqRes = "req";

            //headers
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers.Add("Method", method);
            headers.Add("Session", session);
            headers.Add("Content-Type", contentType);
            headers.Add("Content-Length", body.Length + "");

            CommunicationProtocol sentCommunicationProtocol = new CommunicationProtocol(reqRes, headers, body);

            //send message
            client.Send(sentCommunicationProtocol.ToBytes());

            //receive message
            byte[] receivedBytes = ReceiveAsByteArray(client);
            CommunicationProtocol receivedCommunicationProtocol = CommunicationProtocol.FromBytes(receivedBytes);

            return receivedCommunicationProtocol;
        }

        /// <summary>
        /// Sends a request to the server and receives a response.
        /// </summary>
        /// <param name="method">The method to be used in the request.</param>
        /// <param name="body">The body of the request as a byte array.</param>
        /// <param name="session">The session token for the request.</param>
        /// <returns>The <see cref="CommunicationProtocol"/> object received from the server.</returns>
        public CommunicationProtocol SendAndReceive(string method, byte[] body, string session)
        {
            if (withSSL)
            {
                return SendAndReceiveSSL(method, body, session);
            }

            //create and connect socket
            Socket client = new Socket(serverIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.ReceiveTimeout = receiveTimeout;
            client.Connect(serverEndPoint);

            //req
            string reqRes = "req";

            //headers
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers.Add("Method", method);
            headers.Add("Session", session);
            headers.Add("Content-Length", body.Length + "");

            CommunicationProtocol sentCommunicationProtocol = new CommunicationProtocol(reqRes, headers, body);

            //send message
            client.Send(sentCommunicationProtocol.ToBytes());

            //receive message
            byte[] receivedBytes = ReceiveAsByteArray(client);
            CommunicationProtocol receivedCommunicationProtocol = CommunicationProtocol.FromBytes(receivedBytes);

            return receivedCommunicationProtocol;
        }

        /// <summary>
        /// Receives data from the server as a byte array.
        /// </summary>
        /// <param name="client">The client socket.</param>
        /// <returns>The received data as a byte array.</returns>
        private byte[] ReceiveAsByteArray(Socket client)
        {
            //receive req, res
            byte[] reqResBytes = new byte[3];
            int reqResReceived = client.Receive(reqResBytes);
            if (reqResReceived != reqResBytes.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            //receive header length
            byte[] headerLengthBytes = new byte[6];
            int headerLengthReceived = client.Receive(headerLengthBytes);
            if (headerLengthReceived != headerLengthBytes.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(headerLengthBytes);
            }
            Int32 headerLength = BitConverter.ToInt32(headerLengthBytes, 1);

            //receive headers
            byte[] headers = new byte[headerLength - 9];
            int headersReceived = client.Receive(headers);
            if (headersReceived != headers.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            //get Content-Length header
            string headersStr = Encoding.ASCII.GetString(headers);
            string contentLengthStr = Regex.Match(headersStr, @"Content-Length=[0-9]+").Value;
            int contentLength = int.Parse(contentLengthStr.Split("=")[1]);

            //receive body
            byte[] body = new byte[contentLength];
            int bodyReceived = client.Receive(body);
            if (bodyReceived != body.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            byte[] byteArr = new byte[headerLength + contentLength];
            int byteIdx = 0;

            //req res
            for (int i = 0; i < reqResBytes.Length; i++) byteArr[byteIdx++] = reqResBytes[i];

            //header length
            for (int i = 0; i < headerLengthBytes.Length; i++) byteArr[byteIdx++] = headerLengthBytes[i];

            //headers
            for (int i = 0; i < headers.Length; i++) byteArr[byteIdx++] = headers[i];

            //body
            for (int i = 0; i < body.Length; i++) byteArr[byteIdx++] = body[i];

            return byteArr;
        }

        /// <summary>
        /// Sends a request to the server and receives a response over SSL.
        /// </summary>
        /// <param name="method">The method to be used in the request.</param>
        /// <param name="body">The body of the request as a byte array.</param>
        /// <param name="session">The session token for the request.</param>
        /// <returns>The <see cref="CommunicationProtocol"/> object received from the server.</returns>
        private CommunicationProtocol SendAndReceiveSSL(string method, byte[] body, string session)
        {
            //create and connect socket
            Socket client = new Socket(serverIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.ReceiveTimeout = receiveTimeout;
            client.Connect(serverEndPoint);

            //create ssl stream
            NetworkStream networkStream = new NetworkStream(client, ownsSocket: true);
            SslStream sslStream = new SslStream(networkStream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            //authenticate the server
            sslStream.AuthenticateAsClient("localhost");

            //req
            string reqRes = "req";

            //headers
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers.Add("Method", method);
            headers.Add("Session", session);
            headers.Add("Content-Length", body.Length + "");

            CommunicationProtocol sentCommunicationProtocol = new CommunicationProtocol(reqRes, headers, body);

            //send message
            sslStream.Write(sentCommunicationProtocol.ToBytes());
            sslStream.Flush();

            //receive message
            byte[] receivedBytes = ReceiveAsByteArraySSL(sslStream);
            CommunicationProtocol receivedCommunicationProtocol = CommunicationProtocol.FromBytes(receivedBytes);

            return receivedCommunicationProtocol;
        }

        /// <summary>
        /// Sends a request to the server and receives a response over SSL.
        /// </summary>
        /// <param name="method">The method to be used in the request.</param>
        /// <param name="body">The body of the request as a byte array.</param>
        /// <param name="session">The session token for the request.</param>
        /// <param name="contentType">The content type of the request body.</param>
        /// <returns>The <see cref="CommunicationProtocol"/> object received from the server.</returns>
        private CommunicationProtocol SendAndReceiveSSL(string method, byte[] body, string session, string contentType)
        {
            //create and connect socket
            Socket client = new Socket(serverIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.ReceiveTimeout = receiveTimeout;
            client.Connect(serverEndPoint);

            //create ssl stream
            NetworkStream networkStream = new NetworkStream(client, ownsSocket: true);
            SslStream sslStream = new SslStream(networkStream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            //authenticate the server
            sslStream.AuthenticateAsClient(serverIP.ToString());

            //req
            string reqRes = "req";

            //headers
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers.Add("Method", method);
            headers.Add("Session", session);
            headers.Add("Content-Type", contentType);
            headers.Add("Content-Length", body.Length + "");

            CommunicationProtocol sentCommunicationProtocol = new CommunicationProtocol(reqRes, headers, body);

            //send message
            sslStream.Write(sentCommunicationProtocol.ToBytes());
            sslStream.Flush();

            //receive message
            byte[] receivedBytes = ReceiveAsByteArraySSL(sslStream);
            CommunicationProtocol receivedCommunicationProtocol = CommunicationProtocol.FromBytes(receivedBytes);

            return receivedCommunicationProtocol;
        }

        /// <summary>
        /// Receives data from the server as a byte array over SSL.
        /// </summary>
        /// <param name="sslStream">The SSL stream.</param>
        /// <returns>The received data as a byte array.</returns>
        private byte[] ReceiveAsByteArraySSL(SslStream sslStream)
        {
            //receive req, res
            byte[] reqResBytes = new byte[3];
            int reqResReceived = sslStream.Read(reqResBytes, 0, reqResBytes.Length);
            if (reqResReceived != reqResBytes.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            //receive header length
            byte[] headerLengthBytes = new byte[6];
            int headerLengthReceived = sslStream.Read(headerLengthBytes, 0, headerLengthBytes.Length);
            if (headerLengthReceived != headerLengthBytes.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(headerLengthBytes);
            }
            Int32 headerLength = BitConverter.ToInt32(headerLengthBytes, 1);

            //receive headers
            byte[] headers = new byte[headerLength - 9];
            int headersReceived = sslStream.Read(headers, 0, headers.Length);
            if (headersReceived != headers.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            //get Content-Length header
            string headersStr = Encoding.ASCII.GetString(headers);
            string contentLengthStr = Regex.Match(headersStr, @"Content-Length=[0-9]+").Value;
            int contentLength = int.Parse(contentLengthStr.Split("=")[1]);

            //receive body
            byte[] body = new byte[contentLength];
            int bodyReceived = sslStream.Read(body, 0, body.Length);
            if (bodyReceived != body.Length)
            {
                throw new Exception(); //TBD deal with this or throw costum exception
            }

            byte[] byteArr = new byte[headerLength + contentLength];
            int byteIdx = 0;

            //req res
            for (int i = 0; i < reqResBytes.Length; i++) byteArr[byteIdx++] = reqResBytes[i];

            //header length
            for (int i = 0; i < headerLengthBytes.Length; i++) byteArr[byteIdx++] = headerLengthBytes[i];

            //headers
            for (int i = 0; i < headers.Length; i++) byteArr[byteIdx++] = headers[i];

            //body
            for (int i = 0; i < body.Length; i++) byteArr[byteIdx++] = body[i];

            return byteArr;
        }

        /// <summary>
        /// Validates the server certificate. Currently, it always returns true.
        /// </summary>
        /// <param name="sender">The sender object.</param>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="chain">The certificate chain.</param>
        /// <param name="sslPolicyErrors">Any SSL policy errors.</param>
        /// <returns>true if the certificate is valid; otherwise, false.</returns>
        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            //Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            // Do not allow this client to communicate with unauthenticated servers.
            return true;
        }
    }
}
