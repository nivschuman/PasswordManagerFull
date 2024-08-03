using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PMApplication
{
    /// <summary>
    /// Event args for submitting a password event
    /// </summary>
    public class SubmitPasswordEventArgs : EventArgs
    {
        /// <summary>
        /// The source of the password.
        /// </summary>
        public string Source;

        /// <summary>
        /// The password itself.
        /// </summary>
        public string Password;
    }
}
