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
    /// Page for adding a new password.
    /// </summary>
    public partial class AddPasswordPage : Page
    {
        /// <summary>
        /// Submit event for when submit button is clicked.
        /// </summary>
        public event EventHandler SubmitEvent;

        /// <summary>
        /// Cancel event for when cancel button is clicked.
        /// </summary>
        public event EventHandler CancelEvent;

        /// <summary>
        /// Initiliazes a <see cref="AddPasswordPage"/> class.
        /// </summary>
        public AddPasswordPage()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Tied to generate password button.
        /// Generates a password with <see cref="Password.Generate(int, int)"/> and places it in password text box.
        /// </summary>
        /// <param name="sender">The object which caused the event (generate password button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void GeneratePassword(object sender, EventArgs e)
        {
            PasswordTextBox.Text = Password.Generate(15, 5);
        }

        /// <summary>
        /// Tied to submit button click event, calls submit password event.
        /// Passes submit password event args with source and password from relevant text boxes.
        /// </summary>
        /// <param name="sender">The object which caused the event (submit button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void Submit(object sender, EventArgs e)
        {
            if(SubmitEvent != null)
            {
                SubmitPasswordEventArgs sp = new SubmitPasswordEventArgs();
                sp.Source = SourceTextBox.Text;
                sp.Password = PasswordTextBox.Text;

                SubmitEvent(sender, sp);
            }
        }

        /// <summary>
        /// Tied to cancel button click event, calls cancel event.
        /// </summary>
        /// <param name="sender">The object which caused this event (cancel button).</param>
        /// <param name="e">The event args passed to the event.</param>
        public void Cancel(object sender, EventArgs e)
        {
            if(CancelEvent != null)
            {
                CancelEvent(sender, e);
            }
        }
    }
}
