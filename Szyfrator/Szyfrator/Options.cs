using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;

namespace Szyfrator
{
    public class Options
    {
        public bool ForEncryption { get; set;}

        public String File { get; set; }

        public String Password { get; set; }

        public int Mode { get; set; }

        public int KeySize { get; set; }

        public int BlockSize { get; set; }

        public int SubBlockSize { get; set; }

        public String StoredFileName { get; set; }

        public byte[] InitialVector { get; set; }

        public byte[] SessionKey { get; set; }

        public byte[] EncryptedSessionKey { get; set; }

        public byte[] Content { get; set; }

        public byte[] EncryptedContent { get; set; }

        public List<User> Users { get; set; }

        public Options()
        {
            Users = new List<User>();
            ForEncryption = true;
            Password = null;
            File = null;
            Mode = 0;
            KeySize = 128;
            BlockSize = 128;
            SubBlockSize = 8;
            StoredFileName = null;
            InitialVector = null;
            EncryptedContent = null;
            SessionKey = null;
            EncryptedSessionKey = null;
            Content = null;
        }

        public void AddUser(string name, string pubPath, string privPath)
        {
            Users.Add(new User(name,pubPath,privPath));
        }

    }
}
