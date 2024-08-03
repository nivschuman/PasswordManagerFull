using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PMApplication
{
    /// <summary>
    /// Event args for data about user on login event or create user event.
    /// </summary>
    public class UserEventArgs : EventArgs
    {
        /// <summary>
        /// The name of the public key file chosen for the user.
        /// </summary>
        public string PublicKeyFileName;

        /// <summary>
        /// The name of the private key file chosen for the user.
        /// </summary>
        public string PrivateKeyFileName;

        /// <summary>
        /// The name of the user.
        /// </summary>
        public string UserName;
    }
}
