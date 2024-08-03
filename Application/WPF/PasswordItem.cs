using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PMApplication
{
    /// <summary>
    /// Class to represent a password item in grid of passwords.
    /// </summary>
    public class PasswordItem
    {
        /// <summary>
        /// The source of the password.
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// The password itself.
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Initializes a <see cref="PasswordItem"/> class
        /// </summary>
        /// <param name="source">The source of the password.</param>
        /// <param name="password">The password.</param>
        public PasswordItem(string source, string password)
        {
            Source = source;
            Password = password;
        }
    }
}
