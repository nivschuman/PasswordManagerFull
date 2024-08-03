using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using PasswordManagerClientDLL;
using System.Text.Json;
using System.Security.Cryptography;
using NLog;
using NLog.Config;
using NLog.Targets;
using System.IO;

namespace PMApplication
{
    /// <summary>
    /// Main application window to store pages.
    /// </summary>
    public partial class MainWindow : NavigationWindow
    {
        /// <summary>
        /// Logger variable for logging application events and errors
        /// </summary>
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// <see cref="LoginPage"/> for page to login.
        /// </summary>
        private LoginPage loginPage;

        /// <summary>
        /// <see cref="UserPage"/> for main user activity.
        /// </summary>
        private UserPage userPage;

        /// <summary>
        /// <see cref="AddPasswordPage"/> for adding new password.
        /// </summary>
        private AddPasswordPage addPasswordPage;

        /// <summary>
        /// Username of the logged in user.
        /// </summary>
        private string username;

        /// <summary>
        /// Public key file name for the logged in user.
        /// </summary>
        private string publicKeyFileName;

        /// <summary>
        /// Private key file name for the logged in user.
        /// </summary>
        private string privateKeyFileName;

        /// <summary>
        /// Session token for the logged in user.
        /// </summary>
        private string session;

        /// <summary>
        /// IP Address of the server.
        /// </summary>
        private System.Net.IPAddress serverIP;

        /// <summary>
        /// Port of the server.
        /// </summary>
        private int serverPort;

        /// <summary>
        /// Password manager client for speaking with server, <see cref="PasswordManagerClient"/>.
        /// </summary>
        private PasswordManagerClient pmClient;

        /// <summary>
        /// Initializes main window.
        /// Server IP and server port are initialized.
        /// Password manager client is initialized.
        /// Logger is initialized.
        /// Login page is created and navigated into.
        /// </summary>
        public MainWindow()
        {
            //get data from config file
            string configString = File.ReadAllText("config.json");
            JsonDocument configData = JsonSerializer.Deserialize<JsonDocument>(configString);

            //server connection
            JsonElement serverIPProperty = configData.RootElement.GetProperty("serverIP");
            serverIP = System.Net.IPAddress.Parse(serverIPProperty.GetString());

            JsonElement serverPortProperty = configData.RootElement.GetProperty("serverPort");
            serverPort = serverPortProperty.GetInt32();

            JsonElement withSSLProperty = configData.RootElement.GetProperty("withSSL");
            bool withSSL = withSSLProperty.GetBoolean();

            pmClient = new PasswordManagerClient(serverIP, serverPort, withSSL);

            //initialize logger
            InitializeLog();

            //login page
            loginPage = new LoginPage();
            loginPage.LoginEvent += Login;
            loginPage.CreateUserEvent += CreateUser;

            logger.Info("Started main window with new login page");

            Navigate(loginPage);
        }

        /// <summary>
        /// Initalizes the logger.
        /// Logs are stored in logs directory.
        /// New log file is created on every new date (day,month,year).
        /// A colored console logger is also created.
        /// </summary>
        public static void InitializeLog()
        {
            //create logs directory
            string logsDirectory = "logs";

            if(!Directory.Exists(logsDirectory))
            {
                Directory.CreateDirectory(logsDirectory);
            }

            //get current date
            DateTime now = DateTime.Now;
            string nowDate = now.ToString("dd_MM_yyyy");
            string fileName = $"{nowDate}_logfile.log";

            //logger configuration - file target
            LoggingConfiguration config = new LoggingConfiguration();

            FileTarget fileTarget = new FileTarget("file")
            {
                Name = "LogFile",
                FileName = System.IO.Path.Combine(logsDirectory, fileName),
                Layout = "${longdate}|${level:uppercase=true}|${callsite}|${message}"
            };

            config.AddTarget(fileTarget);
            config.AddRule(LogLevel.Debug, LogLevel.Fatal, fileTarget);

            //logger configuration - colored console target
            ColoredConsoleTarget consoleTarget = new ColoredConsoleTarget()
            {
                Name = "ColoredConsole",
                Layout = "${date:format=HH\\:mm\\:ss} ${level:uppercase=true} ${message}"
            };

            config.AddTarget(consoleTarget);
            config.AddRule(LogLevel.Trace, LogLevel.Fatal, consoleTarget);

            LogManager.Configuration = config;
        }

        /// <summary>
        /// Called through login page, login button click event.
        /// Tries to log in to user with given username, public key file and private key file.
        /// Username, public key file name and private key file name are passed through event args.
        /// On login success new user page is created and navigated to.
        /// New user page is refreshed.
        /// </summary>
        /// <param name="sender">The object which caused the event (login button).</param>
        /// <param name="e">The event args passed to the event (UserEventArgs).</param>
        /// <exception cref="PMClientException">
        /// Thrown by password manager client on socket errors.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown on failure to import RSA key files or decryption failure during login.
        /// </exception>
        private async void Login(object sender, EventArgs e)
        {
            UserEventArgs ue = (UserEventArgs)e;
            username = ue.UserName;
            publicKeyFileName = ue.PublicKeyFileName;
            privateKeyFileName = ue.PrivateKeyFileName;

            logger.Info("Entered login with username: {username}, public key: {publicKey}, private key: {privateKey}", username, publicKeyFileName, privateKeyFileName);

            try
            {
                pmClient.ImportRSAKeys(publicKeyFileName, privateKeyFileName);
            }
            catch(CryptographicException ce)
            {
                MessageBox.Show("Failed to import RSA keys, try using different key files");

                logger.Error("Importing RSA keys failed: {@CryptographicException}", ce);

                return;
            }

            string answerStr = "";

            try
            {
                answerStr = await LoginToUser();
            }
            catch(PMClientException pme)
            {
                if(pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if(pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if(pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }
            catch(CryptographicException ce)
            {
                MessageBox.Show("Decryption failed during login, try using different keys", "Error");

                logger.Error("Decryption failed: {@CryptographicException}", ce);

                return;
            }
            

            if(answerStr != "Success")
            {
                MessageBox.Show(answerStr, "Error");

                logger.Warn("Failed to login to user {username}: {answerStr}", username, answerStr);

                return;
            }

            userPage = new UserPage(username);
            userPage.RefreshEvent += RefreshUserPage;
            userPage.AddPasswordEvent += AddPassword;
            userPage.ShowPasswordEvent += ShowPassword;
            userPage.DeletePasswordEvent += DeletePasswordAction;
            userPage.DeleteAccountEvent += DeleteAccountAction;
            Navigate(userPage);

            logger.Info("Created and navigated to new user page for {username}", username);

            RefreshUserPage(null, null);
        }

        /// <summary>
        /// Called through user page, add password button click event.
        /// Navigates to add password page, creates a page if one has not been created yet.
        /// </summary>
        /// <param name="sender">The object which caused the event (add password button).</param>
        /// <param name="e">The event args passed to the event.</param>
        private void AddPassword(object sender, EventArgs e)
        {
            if(addPasswordPage == null)
            {
                addPasswordPage = new AddPasswordPage();
                addPasswordPage.SubmitEvent += SubmitPassword;
                addPasswordPage.CancelEvent += CancelSubmitPassword;
            }

            Navigate(addPasswordPage);

            logger.Info("Created and navigated to new add password page");
        }

        /// <summary>
        /// Called through add password page, cancel button click event.
        /// Navigates back to user page.
        /// </summary>
        /// <param name="sender">The object which caused the event (cancel button).</param>
        /// <param name="e">The event args passed to the event.</param>
        private void CancelSubmitPassword(object sender, EventArgs e)
        {
            Navigate(userPage);

            logger.Info("Canceled password submission, navigated to userPage");
        }

        /// <summary>
        /// Called through user page, delete account button click.
        /// Requests server to delete the logged in user.
        /// On success navigates to login page.
        /// </summary>
        /// <param name="sender">The object which caused the event (delete account button).</param>
        /// <param name="e">The event args passed to the event.</param>
        /// <exception cref="PMClientException">
        /// Thrown by password manager client on socket errors.
        /// </exception>
        private async void DeleteAccountAction(object sender, EventArgs e)
        {
            MessageBoxResult confirmBox = MessageBox.Show("Are you sure that you want to delete your account?", "Delete Confirmation", MessageBoxButton.YesNo);

            if(confirmBox == MessageBoxResult.No)
            {
                logger.Info("Canceled account delete action, returning");
                return;
            }

            string deleteResult = "";

            try
            {
                deleteResult = await DeleteUser();
            }
            catch (PMClientException pme)
            {
                if (pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }

            if (deleteResult != "Success")
            {
                MessageBox.Show($"Failed to delete user:\n{deleteResult}", "Error");

                logger.Warn("Failed to delete user {username}: {deleteResult}", username, deleteResult);

                return;
            }

            logger.Info("User {username} deleted successfully, returning to login page", username);

            //reset back to new login page
            addPasswordPage = null;
            userPage = null;
            username = "";
            publicKeyFileName = "";
            privateKeyFileName = "";
            session = "";

            loginPage = new LoginPage();
            loginPage.LoginEvent += Login;
            loginPage.CreateUserEvent += CreateUser;

            Navigate(loginPage);
        }

        /// <summary>
        /// Called through user page, delete password button.
        /// Requests server to delete the specified password for logged in user.
        /// specified password is passed through event args.
        /// </summary>
        /// <param name="sender">The object which caused the event (specific delete password button).</param>
        /// <param name="e">The event args passed to the event (password item event args).</param>
        /// <exception cref="PMClientException">
        /// Thrown by password manager client on socket errors.
        /// </exception>
        private async void DeletePasswordAction(object sender, EventArgs e)
        {
            PasswordItemEventArgs passwordItemEV = (PasswordItemEventArgs)e;

            //get passwordItem and delete password with source
            PasswordItem passwordItem = passwordItemEV.PasswordItem;
            
            MessageBoxResult confirmBox = MessageBox.Show("Are you sure that you want to delete this password?", "Delete Confirmation", MessageBoxButton.YesNo);

            if (confirmBox == MessageBoxResult.No)
            {
                logger.Info("Canceled on deleting password with source={source}, returning", passwordItem.Source);

                return;
            }

            string result = "";

            try
            {
                result = await DeletePassword(passwordItem.Source);
            }
            catch (PMClientException pme)
            {
                if (pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }

            if (result != "Success")
            {
                MessageBox.Show($"Failed to delete password:\n{result}", "Error");

                logger.Warn("Failed to delete password with source={source}: {result}", passwordItem.Source, result);

                return;
            }

            logger.Info("Password with source={source} was deleted successfully", passwordItem.Source);

            MessageBox.Show("Password was deleted successfully", "Success");
            userPage.PasswordsDataGrid.Items.Remove(passwordItem);
        }

        /// <summary>
        /// Called through user page, show password button.
        /// Gets password from server and places it onto grid in user page (for logged in user).
        /// Password data is passed through event args.
        /// </summary>
        /// <param name="sender">The object which caused the event (specific show password button).</param>
        /// <param name="e">The event args passed to the event (password item event args).</param>
        /// <exception cref="PMClientException">
        /// Thrown by password manager client on socket errors.
        /// </exception>
        private async void ShowPassword(object sender, EventArgs e)
        {
            PasswordItemEventArgs passwordItemEV = (PasswordItemEventArgs)e;

            //place password inside password item
            PasswordItem passwordItem = passwordItemEV.PasswordItem;

            try
            {
                passwordItem.Password = await GetPassword(passwordItem.Source);
            }
            catch (PMClientException pme)
            {
                if (pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }

            logger.Info("Got password for {source} from server", passwordItem.Source);

            //remove previous item and insert updated item to reflect change
            int idx = userPage.PasswordsDataGrid.Items.IndexOf(passwordItem);
            userPage.PasswordsDataGrid.Items.Remove(passwordItem);
            userPage.PasswordsDataGrid.Items.Insert(idx, passwordItem);
        }

        /// <summary>
        /// Called through add password page, submit button.
        /// Requests server to set specified password with specified source (for logged in user).
        /// Navigates back to user page on success or failure.
        /// </summary>
        /// <param name="sender">The object which caused the event (submit button).</param>
        /// <param name="e">The event args passed to the event (submit password event args).</param>
        /// <exception cref="PMClientException">
        /// Thrown by password manager client on socket errors.
        /// </exception>
        private async void SubmitPassword(object sender, EventArgs e)
        {
            SubmitPasswordEventArgs sp = (SubmitPasswordEventArgs)e;

            string result = "";

            try
            {
                result = await SetPassword(sp.Source, sp.Password);
            }
            catch (PMClientException pme)
            {
                if (pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }

            //prompt user on result
            if (result != "Success")
            {
                MessageBox.Show($"Failed to add password:\n{result}", "Error");

                logger.Warn("Failed to add password for source={source}: {result}", sp.Source, result);
            }
            else
            {
                MessageBox.Show("Password was added successfully", "Success");

                addPasswordPage.SourceTextBox.Text = "";
                addPasswordPage.PasswordTextBox.Text = "";

                logger.Info("Set password successfully for source={source}", sp.Source);
            }

            //return user to user page and refresh it
            Navigate(userPage);

            RefreshUserPage(null, null);
        }

        /// <summary>
        /// Called through user page, refresh button.
        /// Gets all sources for logged in user and displays them onto user page grid.
        /// </summary>
        /// <param name="sender">The object which caused the event (refresh button).</param>
        /// <param name="e">The event args passed to the event.</param>
        /// <exception cref="PMClientException">
        /// Thrown by password manager client on socket errors.
        /// </exception>
        private async void RefreshUserPage(object sender, EventArgs e)
        {
            if(userPage == null)
            {
                return;
            }

            List<string> sources = null;

            try
            {
                sources = await GetSources();
            }
            catch (PMClientException pme)
            {
                if (pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }

            if (sources != null)
            {
                logger.Info("Got sources for user {username}, displaying them", username);

                userPage.DisplaySources(sources);
            }
            else
            {
                MessageBox.Show("Failed to get sources from server", "Error");

                logger.Warn("Failed to get sources for user {username}", username);
            }
        }

        /// <summary>
        /// Called through login page, create user button.
        /// Requests server to create a new user with specified username.
        /// Public and private key files are created for user.
        /// </summary>
        /// <param name="sender">The object which caused the event (create user button).</param>
        /// <param name="e">The event args passed to the event (user event args).</param>
        private async void CreateUser(object sender, EventArgs e)
        {
            UserEventArgs ue = (UserEventArgs)e;
            username = ue.UserName;
            publicKeyFileName = username + "PublicKey";
            privateKeyFileName = username + "PrivateKey";

            pmClient.CreateNewRSAKeys(publicKeyFileName, privateKeyFileName);

            CommunicationProtocol answer = null;
            try
            {
                answer = await Task.Run(() => pmClient.CreateUser(username));
            }
            catch (PMClientException pme)
            {
                if (pme.Reason == PMErrorReason.ConnectionRefused)
                {
                    MessageBox.Show("Failed to connect to server, it may be offline", "Error");

                    logger.Error("Connection to server refused: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.ConnectionTimeouted)
                {
                    MessageBox.Show("Server took too long to respond, it may be offline", "Error");

                    logger.Error("Connection to server timeouted: {@SocketException}", pme.SE);

                    return;
                }
                else if (pme.Reason == PMErrorReason.Unknown)
                {
                    MessageBox.Show("Server connection failed for unkown reason", "Error");

                    logger.Error("Server connection failed: {@SocketException}", pme.SE);

                    return;
                }
            }

            string result = Encoding.ASCII.GetString(answer.Body);

            if(result != "Success")
            {
                MessageBox.Show($"Failed to create user:\n{result}");

                logger.Warn("Failed to create user {username} with public key: {publicKey}, private key: {privateKey} - {result}", username, publicKeyFileName, privateKeyFileName, result);

                return;
            }

            logger.Info("successfully created user {username} with public key: {publicKey}, private key: {privateKey}", username, publicKeyFileName, privateKeyFileName);

            ue.PublicKeyFileName = publicKeyFileName;
            ue.PrivateKeyFileName = privateKeyFileName;

            Login(sender, ue);
        }

        /// <summary>
        /// Async task to delete password from server for logged in user.
        /// Runs pmClient request async with Task.Run.
        /// </summary>
        /// <param name="source">The source for the password to delete is tied to.</param>
        /// <returns>Body success or error message as string.</returns>
        private async Task<string> DeletePassword(string source)
        {
            CommunicationProtocol answer = await Task.Run(() => pmClient.DeletePassword(source, session));

            string answerStr = Encoding.ASCII.GetString(answer.Body);

            return answerStr;
        }

        /// <summary>
        /// Async task to get password with specified source from server (for logged in user).
        /// Runs pmCLient request async with Task.Run.
        /// Decrypts the password before returning it.
        /// </summary>
        /// <param name="source">The source for which the password to get is tied to.</param>
        /// <returns>The decrypted password.</returns>
        private async Task<string> GetPassword(string source)
        {
            CommunicationProtocol answer = await Task.Run(() => pmClient.GetPassword(source, session));

            logger.Debug("Got password, decrypting it");
            string password = pmClient.DecryptPassword(answer.Body);

            return password;
        }

        /// <summary>
        /// Async task to set password with specified source and password in server (for logged in user).
        /// Runs pmClient request async with Task.Run.
        /// In pmClient, password is encrypted before it is uploaded to server.
        /// </summary>
        /// <param name="source">The source for the password</param>
        /// <param name="password">The password itself.</param>
        /// <returns>Body success or error message as string.</returns>
        private async Task<string> SetPassword(string source, string password)
        {
            CommunicationProtocol answer = await Task.Run(() => pmClient.SetPassword(source, password, session));

            string answerStr = Encoding.ASCII.GetString(answer.Body);

            return answerStr;
        }

        /// <summary>
        /// Async task to login to user in server.
        /// Runs login request, then login test.
        /// pmCLient requests are called async using Task.Run.
        /// </summary>
        /// <returns>Success or error message string from login test or login request body.</returns>
        private async Task<string> LoginToUser()
        {
            CommunicationProtocol answer = await Task.Run(() => pmClient.LoginRequest(username));

            if (answer.Body.Length == 0)
            {
                return "Failed to request login";
            }

            session = answer.GetHeaderValue("Session");
            answer = pmClient.LoginTest(answer.Body, session);
            string answerStr = Encoding.ASCII.GetString(answer.Body);

            return answerStr;
        }

        /// <summary>
        /// Async task to get all sources for logged in user from server.
        /// pmClient requests are run async with Task.Run.
        /// </summary>
        /// <returns>List of sources from body or null if no body was returned.</returns>
        private async Task<List<string>> GetSources()
        {
            CommunicationProtocol answer = await Task.Run(() => pmClient.GetSources(session));

            if(answer.Body.Length == 0)
            {
                return null;
            }

            string sourcesJson = Encoding.ASCII.GetString(answer.Body);
            List<string> sources = JsonSerializer.Deserialize<List<string>>(sourcesJson);

            return sources;
        }

        /// <summary>
        /// Async task to delete user logged in user in server.
        /// pmClient request is async using Task.Run.
        /// </summary>
        /// <returns>Success or error message string from body.</returns>
        private async Task<string> DeleteUser()
        {
            CommunicationProtocol answer = await Task.Run(() => pmClient.DeleteUser(session));

            string answerStr = Encoding.ASCII.GetString(answer.Body);

            return answerStr;
        }
    }
}
