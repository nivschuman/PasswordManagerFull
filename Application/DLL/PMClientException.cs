using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace PasswordManagerClientDLL
{
    /// <summary>
    /// Class to represent an exception for a password manager client.
    /// </summary>
    public class PMClientException : Exception
    {
        /// <summary>
        /// The socket exception that was raised.
        /// </summary>
        public SocketException SE;

        /// <summary>
        /// Details of the reason for the exception
        /// </summary>
        public string Details;

        /// <summary>
        /// The <see cref="PMErrorReason"/> reason for the exception.
        /// </summary>
        public PMErrorReason Reason;

        /// <summary>
        /// Initializes a <see cref="PMClientException"/> exception class.
        /// </summary>
        /// <param name="e">The socket exception that was raised.</param>
        public PMClientException(SocketException e)
        {
            SE = e;

            if (e.NativeErrorCode == 10061)
            {
                Reason = PMErrorReason.ConnectionRefused;
                Details = "Connection refused.\r\nNo connection could be made because the target computer actively refused it. This usually results from trying to connect to a service that is inactive on the foreign host—that is, one with no server application running.";
            }
            else if (e.NativeErrorCode == 10060)
            {
                Reason = PMErrorReason.ConnectionTimeouted;
                Details = "Connection timed out.\r\nA connection attempt failed because the connected party did not properly respond after a period of time, or the established connection failed because the connected host has failed to respond.";
            }
            else
            {
                Reason = PMErrorReason.Unknown;
                Details = "Unknown";
            }
        }
    }

    /// <summary>
    /// Reasons for an exception being raised at password manager client.
    /// </summary>
    public enum PMErrorReason
    {
        ConnectionRefused,
        ConnectionTimeouted,
        Unknown
    }
}
