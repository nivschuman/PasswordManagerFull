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
    /// Main page for actions for logged in user.
    /// </summary>
    public partial class UserPage : Page
    {
        /// <summary>
        /// Refresh event for when refresh button is clicked.
        /// </summary>
        public event EventHandler RefreshEvent;

        /// <summary>
        /// Add password event for when add password button is clicked.
        /// </summary>
        public event EventHandler AddPasswordEvent;

        /// <summary>
        /// Show password event for when show password button is clicked.
        /// </summary>
        public event EventHandler ShowPasswordEvent;

        /// <summary>
        /// Delete password event for when delete password button is clicked.
        /// </summary>
        public event EventHandler DeletePasswordEvent;

        /// <summary>
        /// Delete account event for when delete account button is clicked.
        /// </summary>
        public event EventHandler DeleteAccountEvent;

        /// <summary>
        /// Initialized a <see cref="UserPage"/> class.
        /// Initializes a hello label with the appropriate username.
        /// </summary>
        /// <param name="username">username to place in hello label.</param>
        public UserPage(string username)
        {
            InitializeComponent();

            //hello label
            HelloLabel.Content = $"Hello {username}!";

            PasswordsDataGrid.CopyingRowClipboardContent += UpdateClipboardContent;
        }

        /// <summary>
        /// Allows the copying of a password from the password grid onto the clipboard.
        /// </summary>
        /// <param name="sender">The object which caused the event.</param>
        /// <param name="e">The event args passed to the event.</param>
        public void UpdateClipboardContent(object sender, DataGridRowClipboardEventArgs e)
        {
            //get password content
            DataGridClipboardCellContent passwordContent = e.ClipboardRowContent.ElementAt(1);
            string password = passwordContent.Content.ToString().Trim().Replace("\n", "").Replace("\r", "");
            DataGridClipboardCellContent content = new DataGridClipboardCellContent(e.Item, (sender as DataGrid).Columns[0], password);

            //keep only password content in clipboard, remove other rows
            e.ClipboardRowContent.Clear();
            e.ClipboardRowContent.Add(content);
        }

        /// <summary>
        /// Clears passwords data grid and refills it with new sources.
        /// </summary>
        /// <param name="sources">List of sources to fill password data grid with.</param>
        public void DisplaySources(List<string> sources)
        {
            PasswordsDataGrid.Items.Clear();
            foreach(string source in sources)
            {
                PasswordsDataGrid.Items.Add(new PasswordItem(source, ""));
            }
        }

        /// <summary>
        /// Called when a show password button from password data grid is clicked.
        /// Calls the show password event with the relevant password item from grid.
        /// </summary>
        /// <param name="sender">The object which caused the event (show password button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void ShowPassword(object sender, EventArgs e)
        {
            Button showButton = (Button)sender;

            PasswordItem passwordItem = (PasswordItem)showButton.DataContext;

            if(ShowPasswordEvent != null)
            {
                PasswordItemEventArgs passwordItemEV = new PasswordItemEventArgs();
                passwordItemEV.PasswordItem = passwordItem;

                ShowPasswordEvent(sender, passwordItemEV);
            }
        }

        /// <summary>
        /// Called when a delete password button from the password data grid is clicked.
        /// Calls the delete password event with the relevent password item.
        /// </summary>
        /// <param name="sender">The object which caused the event (delete password button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void DeletePassword(object sender, EventArgs e)
        {
            Button showButton = (Button)sender;

            PasswordItem passwordItem = (PasswordItem)showButton.DataContext;

            if (DeletePasswordEvent != null)
            {
                PasswordItemEventArgs passwordItemEV = new PasswordItemEventArgs();
                passwordItemEV.PasswordItem = passwordItem;

                DeletePasswordEvent(sender, passwordItemEV);
            }
        }

        /// <summary>
        /// Called when the add password button is clicked.
        /// Calls the add password event.
        /// </summary>
        /// <param name="sender">The object which caused the event (add password button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void AddPassword(object sender, EventArgs e)
        {
            if(AddPasswordEvent != null)
            {
                //TBD special event args?
                AddPasswordEvent(sender, e);
            }
        }

        /// <summary>
        /// Called when the refresh button is clicked.
        /// Calls the refresh event.
        /// </summary>
        /// <param name="sender">The object which caused the event (refresh button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void Refresh(object sender, EventArgs e)
        {
            if(RefreshEvent != null)
            {
                //TBD special event args?
                RefreshEvent(sender, e);
            }
        }

        /// <summary>
        /// Called when the delete account button is clicked.
        /// Calls the delete account event.
        /// </summary>
        /// <param name="sender">The object which caused the event (delete account button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void DeleteAccount(object sender, EventArgs e)
        {
            if(DeleteAccountEvent != null)
            {
                //TBD special event args?
                DeleteAccountEvent(sender, e);
            }
        }
    }
}
