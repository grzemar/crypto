using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;

namespace Szyfrator
{
    public struct User
    {
        public string Name { get; set; }
        public string PublicKeyPath { get; set; }
        public string PrivateKeyPath { get; set; }

        public User(string name, string publickeypath, string privatekeypath): this()
        {
            Name = name;
            PublicKeyPath = publickeypath;
            PrivateKeyPath = privatekeypath;
        }

        public bool IsValid()
        {
            if (!File.Exists(PublicKeyPath)) return false;
            if (!File.Exists(PrivateKeyPath)) return false;
            return true;
        }
    }
}
