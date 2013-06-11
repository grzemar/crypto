using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;

namespace Szyfrator
{
    public class Options
    {
        private bool forEncryption = true;

        private String file = "";

        private String password = "";

        private int mode = 0;

        private int keySize = 128;

        private int blockSize = 128;

        private int subBlockSize = 1;

        private bool storeFileName = true;

        private String storedFileName = "";

        private byte[] initialVector;

        private byte[] sessionKey;

        private byte[] encryptedSessionKey;

        private byte[] content;

        private byte[] encryptedContent;

        private String[] users = new String[50];

        private string[] publicPath = new string[50];

        private string[] privatePath = new string[50];

        private int usersNumber = 0;

        public Options()
        {
        }

        public bool IsForEncryption()
        {
            return forEncryption;
        }

        public void SetForEncryption(bool forEncryption)
        {
            this.forEncryption = forEncryption;
        }

        public int GetBlockSize()
        {
            return blockSize;
        }

        public void SetBlockSize(int blockSize)
        {
            this.blockSize = blockSize;
        }

        public byte[] GetContent()
        {
            return content;
        }

        public void SetContent(byte[] content)
        {
            this.content = content;
        }

        public byte[] GetEncryptedContent()
        {
            return encryptedContent;
        }

        public void SetEncryptedContent(byte[] encryptedContent)
        {
            this.encryptedContent = encryptedContent;
        }

        public byte[] GetEncryptedSessionKey()
        {
            return encryptedSessionKey;
        }

        public void SetEncryptedSessionKey(byte[] encryptedSessionKey)
        {
            this.encryptedSessionKey = encryptedSessionKey;
        }

        public String GetFile()
        {
            return file;
        }

        public void SetFile(String file)
        {
            this.file = file;
        }

        public byte[] GetInitialVector()
        {
            return initialVector;
        }

        public void SetInitialVector(byte[] initialVector)
        {
            this.initialVector = initialVector;
        }

        public int GetKeySize()
        {
            return keySize;
        }

        public void SetKeySize(int keySize)
        {
            this.keySize = keySize;
        }

        public int GetMode()
        {
            return mode;
        }

        public void SetMode(int mode)
        {
            this.mode = mode;
        }

        public String GetPassword()
        {
            return password;
        }

        public void SetPassword(String password)
        {
            this.password = password;
        }

        public byte[] GetSessionKey()
        {
            return sessionKey;
        }

        public void SetSessionKey(byte[] sessionKey)
        {
            this.sessionKey = sessionKey;
        }

        public bool IsStoreFileName()
        {
            return storeFileName;
           
        }

        public void SetStoreFileName(bool storeFileName)
        {
            this.storeFileName = storeFileName;
        }

        public int GetSubBlockSize()
        {
            return subBlockSize;
        }

        public void SetSubBlockSize(int subBlockSize)
        {
            this.subBlockSize = subBlockSize;
        }

        private void SetStoredFileName(String fileName)
        {
            this.storedFileName = fileName;
        }

        public String GetStoredFileName()
        {
            return storedFileName;
        }

        public int GetUsersNumber()
        {
            return usersNumber;
        }

        public void SetUsersNumber(int i)
        {
            usersNumber = i;
        }

        public void AddUser(String added, string pubPath, string privPath)
        {
            users[usersNumber] = added;
            publicPath[usersNumber] = pubPath;
            privatePath[usersNumber] = privPath;
            usersNumber++;
        }

        public String[] GetUsers()
        {
            return users;
        }

        public string[] GetPublicKeys()
        {
            return publicPath;
        }

        public string[] GetPrivateKeys()
        {
            return privatePath;
        }
    }
}
