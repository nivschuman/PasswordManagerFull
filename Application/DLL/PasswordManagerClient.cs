using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace PasswordManagerClientDLL
{
    /// <summary>
    /// Represents a client for the password manager application.
    /// </summary>
    public class PasswordManagerClient
    {
        /// <summary>
        /// Communication protocol client to use to speak with server.
        /// </summary>
        private Client client;

        /// <summary>
        /// The RSA public key and private key service provider.
        /// </summary>
        private RSACryptoServiceProvider csp;

        /// <summary>
        /// The name of the directory in which private and public keys are stored.
        /// </summary>
        private string keysDirectoryName;

        /// <summary>
        /// Initializes a <see cref="PasswordManagerClient"/> class with the specified serverIP and serverPort.
        /// Uses default values for keysDirectoryName ("keys") and SSL usage (true).
        /// </summary>
        /// <param name="serverIP">The IP adress of the server.</param>
        /// <param name="serverPort">The port of the server.</param>
        public PasswordManagerClient(IPAddress serverIP, int serverPort) : this(serverIP, serverPort, "keys", true)
        {
        }

        /// <summary>
        /// Initializes a <see cref="PasswordManagerClient"/> class with the specified serverIP, serverPort and SSL usage.
        /// Uses default value for keysDirectoryName ("keys").
        /// </summary>
        /// <param name="serverIP">The IP address of the server.</param>
        /// <param name="serverPort">The port of the server.</param>
        /// <param name="withSSL">Indicates whether to use SSL or not.</param>
        public PasswordManagerClient(IPAddress serverIP, int serverPort, bool withSSL) : this(serverIP, serverPort, "keys", withSSL)
        {
        }

        /// <summary>
        /// Initializes a <see cref="PasswordManagerClient"/> class with the specified serverIP, serverPort, keys directory name and SSL usage.
        /// </summary>
        /// <param name="serverIP">The IP address of the server.</param>
        /// <param name="serverPort">The port of the server.</param>
        /// <param name="keysDirectoryName">The name of the keys directory.</param>
        /// <param name="withSSL">Indicates whether to use SSL or not.</param>
        public PasswordManagerClient(IPAddress serverIP, int serverPort, string keysDirectoryName, bool withSSL)
        {
            client = new Client(serverIP, serverPort, withSSL);
            csp = new RSACryptoServiceProvider(2048);

            this.keysDirectoryName = keysDirectoryName;

            if (!Directory.Exists(keysDirectoryName))
            {
                Directory.CreateDirectory(keysDirectoryName);
            }
        }

        /// <summary>
        /// Imports RSA service provider keys from public key file and private key file.
        /// The public key and private key in the files should be in the PKCS#1 format.
        /// </summary>
        /// <param name="publicKeyFileName">The name of the public key file.</param>
        /// <param name="privateKeyFileName">The name of the private key file.</param>
        public void ImportRSAKeys(string publicKeyFileName, string privateKeyFileName)
        {
            int read;

            if (File.Exists(publicKeyFileName))
            {
                csp.ImportRSAPublicKey(File.ReadAllBytes(publicKeyFileName), out read);
            }

            if (File.Exists(privateKeyFileName))
            {
                csp.ImportRSAPrivateKey(File.ReadAllBytes(privateKeyFileName), out read);
            }
        }

        /// <summary>
        /// Generates new 2048 bit RSA public key and private key and stores them in files.
        /// Files are stored inside keys directory.
        /// </summary>
        /// <param name="publicKeyFileName">The name of the file with the public key.</param>
        /// <param name="privateKeyFileName">The name of the file with the private key.</param>
        public void CreateNewRSAKeys(string publicKeyFileName, string privateKeyFileName)
        {
            csp = new RSACryptoServiceProvider(2048);

            string publicKeyPath = Path.Combine(keysDirectoryName, publicKeyFileName);
            string privateKeyPath = Path.Combine(keysDirectoryName, privateKeyFileName);

            File.WriteAllBytes(publicKeyPath, csp.ExportRSAPublicKey());
            File.WriteAllBytes(privateKeyPath, csp.ExportRSAPrivateKey());
        }

        /// <summary>
        /// Sends request to server to create new user with csp public key and given username.
        /// </summary>
        /// <param name="userName">The username for the user to be created.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response.</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol CreateUser(string userName)
        {
            string publicKey = System.Convert.ToBase64String(csp.ExportRSAPublicKey());

            string body = $"{{\"userName\":\"{userName}\",\"publicKey\":\"{publicKey}\"}}";
            byte[] bodyBytes = Encoding.ASCII.GetBytes(body);

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("create_user", bodyBytes, "-", "json");
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Sends a login request to the server for user with userName as username.
        /// </summary>
        /// <param name="userName">The name of the user to login to.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is random 64 bit encrypted number).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol LoginRequest(string userName)
        {
            byte[] bodyBytes = Encoding.ASCII.GetBytes(userName);
            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("login_request", bodyBytes, "*", "ascii");
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Send login test request to server after having sent a login request.
        /// Random 64 bit number is decrypted using csp private key and is passed to server for verification.
        /// </summary>
        /// <param name="encryptedNumber">The random encrypted 64 bit number that the server returned at login request.</param>
        /// <param name="loginSession">The session token for the session that the server generated and returned at login request.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is success or error message).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol LoginTest(byte[] encryptedNumber, string loginSession)
        {
            byte[] decryptedNumber = csp.Decrypt(encryptedNumber, false);

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("login_test", decryptedNumber, loginSession, "bytes");
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Request server to return list of all password sources for logged in user.
        /// </summary>
        /// <param name="loginSession">The session token for the session generated at login.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is json list of sources).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol GetSources(string loginSession)
        {
            byte[] emptyBody = new byte[0];

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("get_sources", emptyBody, loginSession);
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Request server to return password for specified source for logged in user.
        /// </summary>
        /// <param name="source">The source of the password.</param>
        /// <param name="loginSession">The session token for the session generated at login.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is encrypted password).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol GetPassword(string source, string loginSession)
        {
            byte[] bodyBytes = Encoding.ASCII.GetBytes(source);

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("get_password", bodyBytes, loginSession, "ascii");
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }


            return answer;
        }

        /// <summary>
        /// Request server to set password for source for the logged in user.
        /// Password is encrypted with csp public key before it is sent to server.
        /// </summary>
        /// <param name="source">The source of the password.</param>
        /// <param name="password">The password.</param>
        /// <param name="loginSession">The session token for the session generated at login.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is success or error message).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol SetPassword(string source, string password, string loginSession)
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] encodedPassword = csp.Encrypt(passwordBytes, false);
            string encodedPasswordStr = System.Convert.ToBase64String(encodedPassword);

            string bodyJson = $"{{\"source\": \"{source}\", \"password\": \"{encodedPasswordStr}\"}}";
            byte[] bodyBytes = Encoding.ASCII.GetBytes(bodyJson);

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("set_password", bodyBytes, loginSession, "json");
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Request server to delete the password of source for logged in user.
        /// </summary>
        /// <param name="source">The source of the password.</param>
        /// <param name="loginSession">The session token for the session generated at login.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is success or error message).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol DeletePassword(string source, string loginSession)
        {
            byte[] bodyBytes = Encoding.ASCII.GetBytes(source);

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("delete_password", bodyBytes, loginSession, "ascii");
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Request server to delete the logged in user.
        /// </summary>
        /// <param name="loginSession">The session token for the session generated at login.</param>
        /// <returns><see cref="CommunicationProtocol"/> object representing server response (body is success or error message).</returns>
        /// <exception cref="PMClientException">
        /// Thrown when sockets exceptions are thrown at client.
        /// </exception>
        public CommunicationProtocol DeleteUser(string loginSession)
        {
            byte[] emptyBody = new byte[0];

            CommunicationProtocol answer;

            try
            {
                answer = client.SendAndReceive("delete_user", emptyBody, loginSession);
            }
            catch (SocketException e)
            {
                PMClientException pme = new PMClientException(e);

                throw pme;
            }

            return answer;
        }

        /// <summary>
        /// Decryptes an encrypted password using csp private key.
        /// Password should have been encrypted with matching csp public key.
        /// </summary>
        /// <param name="encryptedPassword">The encrypted password as byte array.</param>
        /// <returns>The password as a string.</returns>
        public string DecryptPassword(byte[] encryptedPassword)
        {
            byte[] decryptedPassword = csp.Decrypt(encryptedPassword, false);
            string decryptedPasswordStr = Encoding.ASCII.GetString(decryptedPassword);

            return decryptedPasswordStr;
        }
    }
}
