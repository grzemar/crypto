using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;

namespace Szyfrator
{
    public class CryptOptions
    {
        public bool ForEncryption { get; set;}

        public String FilePath { get; set; }

        public String Password { get; set; }

        public int Mode { get; set; }

        public int KeySize { get; set; }

        public int BlockSize { get; set; }

        public int SubBlockSize { get; set; }

        public byte[] InitialVector { get; set; }

        public byte[] SessionKey { get; set; }

        public byte[] EncryptedSessionKey { get; set; }

        public byte[] Content { get; set; }

        public byte[] EncryptedContent { get; set; }

        public List<User> Users { get; set; }

        public CryptOptions()
        {
            Users = new List<User>();
            ForEncryption = true;
            Password = null;
            FilePath = null;
            Mode = 0;
            KeySize = 128;
            BlockSize = 128;
            SubBlockSize = 8;
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

        public string Validate()
        {
            StringBuilder message = new StringBuilder();
            bool isValid = true;
            if (FilePath == null || !File.Exists(FilePath))
            {
                message.Append("specify file path\n");
                isValid = false;
            }
            if (ForEncryption == true && Users.Count < 1)
            {
                message.Append("grant privileges to file to users\n");
                isValid = false;
            }

            if (ForEncryption == false && Users.Count != 1)
            {
                message.Append("select user to access file\n");
                isValid = false;
            }
            foreach (User u in Users)
                if (u.IsValid() == false)
                {
                    message.Append("some user keys paths are broken, fix config file");
                    isValid = false;
                    break;
                }
            
            if (isValid == true) return "OK";
            return message.ToString();
        }
    }
}
