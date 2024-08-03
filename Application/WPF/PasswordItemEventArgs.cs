using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PMApplication
{
    /// <summary>
    /// Event args class for events which were called on specific password item.
    /// </summary>
    public class PasswordItemEventArgs : EventArgs
    {
        /// <summary>
        /// The password item tied to the called event.
        /// </summary>
        public PasswordItem PasswordItem;
    }
}
