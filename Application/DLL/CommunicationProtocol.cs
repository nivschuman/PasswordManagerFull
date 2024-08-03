using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordManagerClientDLL
{
    /// <summary>
    /// Represents a communication protocol message.
    /// </summary>
    public class CommunicationProtocol
    {
        /// <summary>
        /// String to state whether message is request (req) or response (res).
        /// </summary>
        private string reqRes;

        /// <summary>
        /// Contains all message headers, key is header name and value is header value.
        /// </summary>
        private Dictionary<string, string> headers;

        /// <summary>
        /// The body of the message as a byte array.
        /// </summary>
        private byte[] body;

        /// <summary>
        /// Public Body to get body attribute.
        /// </summary>
        public byte[] Body
        {
            get
            {
                return body;
            }
        }

        /// <summary>
        /// Turns message into string, reqRes:headerName=headerValue...:\nbody format.
        /// </summary>
        /// <returns>Formatted string of message.</returns>
        public override string ToString()
        {
            string headersStr = String.Join(":", headers.Select(kvp => $"{kvp.Key}={kvp.Value}"));

            return $"{reqRes}:{headersStr}:\n{BitConverter.ToString(body)}";
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CommunicationProtocol"/> class with the specified reqRes, headers and body.
        /// </summary>
        /// <param name="reqRes">Request (req) or response (res) string.</param>
        /// <param name="headers">Message headers where key is header name, value is header value.</param>
        /// <param name="body">The body of the message in bytes.</param>
        public CommunicationProtocol(string reqRes, Dictionary<string, string> headers, byte[] body)
        {
            this.reqRes = reqRes;
            this.headers = headers;
            this.body = body;
        }

        /// <summary>
        /// Get the value of the header with the specified header name.
        /// </summary>
        /// <param name="headerName">The name of the header.</param>
        /// <returns>The value of the header with header name.</returns>
        public string GetHeaderValue(string headerName)
        {
            return headers[headerName];
        }

        /// <summary>
        /// Set the value of a header with the specified header name.
        /// </summary>
        /// <param name="headerName">The name of the header.</param>
        /// <param name="headerValue">The value to set the header to.</param>
        public void SetHeaderValue(string headerName, string headerValue)
        {
            headers[headerName] = headerValue;
        }

        /// <summary>
        /// Turns the message into bytes format.
        /// </summary>
        /// <returns>The message as a byte array.</returns>
        public byte[] ToBytes()
        {
            int paramsLength = 0;

            foreach (KeyValuePair<string, string> kvp in headers)
            {
                paramsLength += kvp.Key.Length + "=".Length + kvp.Value.Length + ":".Length;
            }

            Int32 headerLength = 6 + reqRes.Length + paramsLength;

            int bodyLength = body == null ? 0 : body.Length;
            byte[] byteArr = new byte[headerLength + bodyLength];
            int byteIdx = 0;

            //byteArr[0:3] = reqRes
            byte[] reqResBytes = Encoding.ASCII.GetBytes(reqRes);
            for (int i = 0; i < reqResBytes.Length; i++) byteArr[byteIdx++] = reqResBytes[i];

            //byteArr[3:4] = ":"
            byteArr[byteIdx++] = Encoding.ASCII.GetBytes(":")[0];

            //byteArr[4:8] = headerLength as 4 byte int in little endian
            byte[] headerLengthBytes = BitConverter.GetBytes(headerLength);
            if (!BitConverter.IsLittleEndian) Array.Reverse(headerLengthBytes);
            for (int i = 0; i < headerLengthBytes.Length; i++) byteArr[byteIdx++] = headerLengthBytes[i];

            //byteArr[8:9] = ":"
            byteArr[byteIdx++] = Encoding.ASCII.GetBytes(":")[0];

            foreach (KeyValuePair<string, string> kvp in headers)
            {
                byte[] headerNameBytes = Encoding.ASCII.GetBytes(kvp.Key);
                for (int j = 0; j < headerNameBytes.Length; j++) byteArr[byteIdx++] = headerNameBytes[j];

                byteArr[byteIdx++] = Encoding.ASCII.GetBytes("=")[0];

                byte[] headerValueBytes = Encoding.ASCII.GetBytes(kvp.Value);
                for (int j = 0; j < headerValueBytes.Length; j++) byteArr[byteIdx++] = headerValueBytes[j];

                byteArr[byteIdx++] = Encoding.ASCII.GetBytes(":")[0];
            }

            for (int i = 0; i < bodyLength; i++)
            {
                byteArr[byteIdx++] = body[i];
            }

            return byteArr;
        }

        /// <summary>
        /// Generates a <see cref="CommunicationProtocol"/> object from a bytes representation of it.
        /// </summary>
        /// <param name="byteArr">The byte array which represents the communication protocol message.</param>
        /// <returns>A <see cref="CommunicationProtocol"/> object representation of the message.</returns>
        public static CommunicationProtocol FromBytes(byte[] byteArr)
        {
            //req res
            byte[] reqResBytes = new byte[3];
            for (int i = 0; i < reqResBytes.Length; i++) reqResBytes[i] = byteArr[i];
            string reqRes = Encoding.ASCII.GetString(reqResBytes);

            if (reqRes != "req" && reqRes != "res")
            {
                return null; // TBD throw custom exception
            }

            //header length with little endian conversion
            byte[] headerLengthBytes = new byte[4];
            int byteIdx = 4;
            for (int i = 0; i < 4; i++) headerLengthBytes[i] = byteArr[byteIdx++];

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(headerLengthBytes);
            }

            Int32 headerLength = BitConverter.ToInt32(headerLengthBytes, 0);

            //headers
            Dictionary<string, string> headers = new Dictionary<string, string>();

            string headerName = "";
            string headerValue = "";
            bool isHeaderName = true;
            byteIdx = 9;

            while (byteIdx < headerLength)
            {
                if (byteArr[byteIdx] == Encoding.ASCII.GetBytes(":")[0])
                {
                    headers[headerName] = headerValue;

                    headerName = "";
                    headerValue = "";
                    isHeaderName = true;
                }
                else if (byteArr[byteIdx] == Encoding.ASCII.GetBytes("=")[0])
                {
                    isHeaderName = false;
                }
                else if (isHeaderName)
                {
                    byte[] charByte = { byteArr[byteIdx] };
                    headerName += Encoding.ASCII.GetString(charByte);
                }
                else
                {
                    byte[] charByte = { byteArr[byteIdx] };
                    headerValue += Encoding.ASCII.GetString(charByte);
                }

                byteIdx++;
            }

            //body
            byte[] body = new byte[byteArr.Length - headerLength];
            for (int i = 0; i < body.Length; i++) body[i] = byteArr[byteIdx++];

            return new CommunicationProtocol(reqRes, headers, body);
        }
    }
}
