using Microsoft.Win32;
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

namespace PMApplication
{
    /// <summary>
    /// Page for logging in or creating new user.
    /// </summary>
    public partial class LoginPage : Page
    {
        /// <summary>
        /// Login event for when login button is clicked.
        /// </summary>
        public event EventHandler LoginEvent;

        /// <summary>
        /// Create user event for when create user button is clicked.
        /// </summary>
        public event EventHandler CreateUserEvent;

        /// <summary>
        /// Name of the chosen private key file.
        /// </summary>
        private string privateKeyFileName;

        /// <summary>
        /// Name of the chosen public key file.
        /// </summary>
        private string publicKeyFileName;

        /// <summary>
        /// Initializes a <see cref="LoginPage"/> class.
        /// Ties button click events to their appropriate functions.
        /// </summary>
        public LoginPage()
        {
            InitializeComponent();

            publicKeyChooseFileButton.Click += ChooseFileButtonClick;
            privateKeyChooseFileButton.Click += ChooseFileButtonClick;

            loginButton.Click += Login;
            newUserButton.Click += CreateUser;
        }

        /// <summary>
        /// Called when login button is clicked.
        /// Calls the login event with public key file name, private key file name and username from textbox.
        /// </summary>
        /// <param name="sender">The object which caused the event (login button).</param>
        /// <param name="e">The event args that are passed to the event.</param>
        private void Login(object sender, EventArgs e)
        {
            if(LoginEvent != null)
            {
                UserEventArgs userEventArgs = new UserEventArgs();
                userEventArgs.PublicKeyFileName = publicKeyFileName;
                userEventArgs.PrivateKeyFileName = privateKeyFileName;
                userEventArgs.UserName = usernameTextBox.Text;
                
                LoginEvent(sender, userEventArgs);
            }
        }

        /// <summary>
        /// Called when create user button is clicked.
        /// Calls the create user event with public key file name, private key file name and username from textbox.
        /// </summary>
        /// <param name="sender">The object which caused the event (create user button).</param>
        /// <param name="e">The event args that are passed to the event.</param>
        private void CreateUser(object sender, EventArgs e)
        {
            if(CreateUserEvent != null)
            {
                UserEventArgs userEventArgs = new UserEventArgs();
                userEventArgs.PublicKeyFileName = publicKeyFileName;
                userEventArgs.PrivateKeyFileName = privateKeyFileName;
                userEventArgs.UserName = usernameTextBox.Text;

                CreateUserEvent(sender, userEventArgs);
            }
        }

        /// <summary>
        /// Called when public/private key choose file button is clicked.
        /// Lets the user choose a file and shows it onto appropriate label.
        /// </summary>
        /// <param name="sender">The object which caused the event (public/private key choose file button).</param>
        /// <param name="e">The event args passed to the event.</param>
        private void ChooseFileButtonClick(object sender, EventArgs e)
        {
            bool publicKey = sender == publicKeyChooseFileButton;
            string fileName = ChooseFile();

            publicKeyFileName = publicKey ? fileName : publicKeyFileName;
            privateKeyFileName = !publicKey ? fileName : privateKeyFileName;

            publicKeyFileLabel.Content = publicKeyFileName;
            publicKeyFileLabel.ToolTip = publicKeyFileName;

            privateKeyFileLabel.Content = privateKeyFileName;
            privateKeyFileLabel.ToolTip = privateKeyFileName;
        }

        /// <summary>
        /// Function to open dialog for user to choose a file.
        /// </summary>
        /// <returns>The name of the chosen file.</returns>
        private string ChooseFile()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            if(openFileDialog.ShowDialog() == true)
            {
                return openFileDialog.FileName;
            }

            return null;
        }
    }
}
