using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.IO;
using System.Text;
using System.Xml;
using System.Windows.Forms;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;

namespace Szyfrator
{
    public partial class Form1 : Form
    {
        private Crypt cryptor;
        private const string config = "Resources\\keys.csv";
        private string[] names = new string[50];
        private string[] publicKeyPath = new string[50];
        private string[] privateKeyPath = new string[50];
        private int lines = 0;
        private string tmpPublic;
        private string tmpPrivate;
        public Form1()
        {
            InitializeComponent();
            CryptOptions opts = new CryptOptions();
            cryptor = new Crypt(opts);
            try
            {
                using (StreamReader readFile = new StreamReader(config))
                {
                    string row;
                    string[] column;
                    while ((row = readFile.ReadLine()) != null)
                    {
                        column = row.Split(';');
                        names[lines] = column[0];
                        publicKeyPath[lines] = column[1];
                        privateKeyPath[lines] = column[2];
                        checkedListBox1.Items.Insert(lines, names[lines]);
                        listBox4.Items.Insert(lines, names[lines]);
                        lines++;
                    }
                }
            }
            catch (Exception)
            {
                MessageBox.Show("Program encountered errors while trying to read config file");
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog dialog1 = new OpenFileDialog();
            dialog1.Title = "Open file for encryption";
            dialog1.InitialDirectory = @"C:\";
            if (dialog1.ShowDialog() == DialogResult.OK)
            {
                cryptor.GetOpts().FilePath = dialog1.FileName;
                label12.Text = dialog1.FileName;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            switch(listBox3.SelectedIndex)
            {
                case 0: cryptor.GetOpts().SubBlockSize = 8;
                    break;
                case 1: cryptor.GetOpts().SubBlockSize = 16;
                    break;
                case 2: cryptor.GetOpts().SubBlockSize = 32;
                    break;
                case 3: cryptor.GetOpts().SubBlockSize = 64;
                    break;
                default: cryptor.GetOpts().SubBlockSize = 64;
                    break;
            }
            cryptor.GetOpts().Mode =listBox2.SelectedIndex;
            cryptor.GetOpts().ForEncryption = true;
            cryptor.GetOpts().FilePath = label12.Text;
            cryptor.GetOpts().Users = new List<User>();

            if (listBox1.SelectedIndex == 0) cryptor.GetOpts().KeySize = 128;
            if (listBox1.SelectedIndex == 1) cryptor.GetOpts().KeySize = 192;
            if (listBox1.SelectedIndex == 2) cryptor.GetOpts().KeySize = 256;
            cryptor.GetOpts().Mode = listBox2.SelectedIndex;
            for (int kk = 0; kk < lines; kk++)
            {
                if (checkedListBox1.GetItemChecked(kk))
                {
                    cryptor.GetOpts().AddUser(names[kk], publicKeyPath[kk],privateKeyPath[kk]);
                }
            }
            string message = cryptor.GetOpts().Validate();
            if (message.CompareTo("OK") != 0)
            {
                MessageBox.Show(message);
                return;
            }
            cryptor.GetOpts().Content = ReadByteArrayFromFile(cryptor.GetOpts().FilePath);
            SaveFileDialog dialog2 = new SaveFileDialog();
            dialog2.Title = "Save encrypted file";
            dialog2.InitialDirectory = @"C:\";
            if ((dialog2.ShowDialog() == DialogResult.OK) && (!dialog2.FileName.Equals(cryptor.GetOpts().FilePath)))
            {
                int j = cryptor.GetOpts().Mode;
                string cipherMode = "";
                switch(j)
                {
                    case 0: cipherMode = "ECB";
                            break;
                    case 1: cipherMode = "CBC";
                            break;
                    case 2: cipherMode = "CFB";
                            break;
                    case 3: cipherMode = "OFB";
                            break;
                    default: break;
                }
                cryptor.GetOpts().SessionKey = cryptor.GenerateSessionKey(cryptor.GetOpts().KeySize);
             
                cryptor.Encrypt();

                byte[] initVec = cryptor.GetOpts().InitialVector;
                string destination = dialog2.FileName;

                SaveAsXml(cryptor, cipherMode, destination);
                
            }
            else MessageBox.Show("Path not valid");
        }

        private void SaveAsXml(Crypt cryptor, string cipherMode,string destination)
        {
            using (XmlWriter writer = XmlWriter.Create(destination))
            {
                writer.WriteStartDocument();
                writer.WriteStartElement("EncryptedFile");

                writer.WriteStartElement("EncryptedFileHeader");

                writer.WriteElementString("Algorithm", "RC6");
                writer.WriteElementString("KeySize", cryptor.GetOpts().KeySize.ToString());
                if (String.Compare("CFB", cipherMode) == 0 || String.Compare("OFB", cipherMode) == 0) 
                    writer.WriteElementString("SubBlockSize", cryptor.GetOpts().SubBlockSize.ToString());
                writer.WriteElementString("CipherMode", cipherMode);
                writer.WriteElementString("IV", Convert.ToBase64String(cryptor.GetOpts().InitialVector));

                writer.WriteStartElement("ApprovedUsers");

                foreach (User u in cryptor.GetOpts().Users)
                {
                    writer.WriteStartElement("User");
                    writer.WriteElementString("Name", u.Name);
                    string pubpath = u.PublicKeyPath;

                    using (StreamReader reader = new StreamReader(pubpath))
                    {
                        String elo = reader.ReadToEnd();
                        byte[] publicKey = Convert.FromBase64String(elo);
                        RsaKeyParameters pubKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKey);
                        byte[] encSessionKey = cryptor.RsaEncrypt(cryptor.GetOpts().SessionKey, pubKey);
                        writer.WriteElementString("SessionKey", Convert.ToBase64String(encSessionKey));

                    }
                    writer.WriteEndElement();
                }

                writer.WriteEndElement();

                writer.WriteEndElement();

                writer.WriteStartElement("Content");

                writer.WriteString(Convert.ToBase64String(cryptor.GetOpts().EncryptedContent));

                writer.WriteEndElement();

                writer.WriteEndElement();
                writer.WriteEndDocument();
                MessageBox.Show("File encrypted");
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            OpenFileDialog dialog1 = new OpenFileDialog();
            dialog1.Title = "Open file for decryption";
            dialog1.InitialDirectory = @"C:\";
            if (dialog1.ShowDialog() == DialogResult.OK)
            {
                cryptor.GetOpts().FilePath = dialog1.FileName;
                label13.Text = dialog1.FileName;
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            cryptor.GetOpts().ForEncryption = false;
            cryptor.GetOpts().Password = textBox4.Text;
            cryptor.GetOpts().FilePath = label13.Text;
            SaveFileDialog dialog2 = new SaveFileDialog();
            dialog2.Title = "Save decrypted file as";
            dialog2.InitialDirectory = @"C:\";
            cryptor.GetOpts().Users = new List<User>();
            int kk = listBox4.SelectedIndex;
            if (kk<0) kk = 0;
            cryptor.GetOpts().AddUser(names[kk], publicKeyPath[kk], privateKeyPath[kk]);
            string message = cryptor.GetOpts().Validate();
            if (message.CompareTo("OK") != 0)
            {
                MessageBox.Show(message);
                return;
            }
            if ((dialog2.ShowDialog() == DialogResult.OK) && (!dialog2.FileName.Equals(cryptor.GetOpts().FilePath)))
            {
                string source = cryptor.GetOpts().FilePath;
                
                int success = readFromXml(cryptor, source);
                if (success == 0)
                {
                    cryptor.Decrypt();
                    bool enc = WriteByteArrayToFile(cryptor.GetOpts().Content, dialog2.FileName);
                    MessageBox.Show("File decrypted");
                }
                else
                    MessageBox.Show("Encountered exception while trying to decrypt file.");
            }
            else MessageBox.Show("Path not valid");
        }

        private int readFromXml(Crypt cryptor,string source)
        {
            using (XmlReader reader = XmlReader.Create(source))
            {
                try
                {
                    reader.ReadStartElement("EncryptedFile");
                    reader.ReadStartElement("EncryptedFileHeader");

                    reader.ReadStartElement("Algorithm");
                    reader.ReadString();
                    reader.ReadEndElement();
                    reader.ReadStartElement("KeySize");
                    string z = reader.ReadString();
                    cryptor.GetOpts().KeySize = Convert.ToInt32(z);
                    reader.ReadEndElement();

                    try
                    {
                        reader.ReadStartElement("SubBlockSize");
                        z = reader.ReadString();
                        cryptor.GetOpts().SubBlockSize = Convert.ToInt32(z);
                        reader.ReadEndElement();
                    }
                    catch (Exception)
                    {
                    }
                    reader.ReadStartElement("CipherMode");
                    z = reader.ReadString();
                    int i = 0;
                    if ((String.Compare(z, "ECB")) == 0) i = 0;
                    if ((String.Compare(z, "CBC")) == 0) i = 1;
                    if ((String.Compare(z, "CFB")) == 0) i = 2;
                    if ((String.Compare(z, "OFB")) == 0) i = 3;
                    cryptor.GetOpts().Mode = i;

                    reader.ReadEndElement();

                    reader.ReadStartElement("IV");
                    z = reader.ReadString();
                    cryptor.GetOpts().InitialVector = Convert.FromBase64String(z);
                    reader.ReadEndElement();

                    reader.ReadStartElement("ApprovedUsers");
                    String stri = cryptor.GetOpts().Users[0].Name;
                    int usersInXml = 1;
                    int setIt = 0;
                    cryptor.GetOpts().SessionKey = cryptor.GenerateSessionKey(cryptor.GetOpts().KeySize);
                    while (usersInXml == 1)
                    {
                        try
                        {
                            reader.ReadStartElement("User");

                            reader.ReadStartElement("Name");
                            String nameUser = reader.ReadString();
                            if (nameUser.Equals(stri)) setIt = 1;

                            reader.ReadEndElement();

                            reader.ReadStartElement("SessionKey");
                            z = reader.ReadString();
                            if (setIt == 1)
                            {
                                setIt = 0;
                                string privpath = cryptor.GetOpts().Users[0].PrivateKeyPath;
                                readPrivateKey(privpath,z);
                            }
                            reader.ReadEndElement();
                            reader.ReadEndElement();
                        }
                        catch (Exception)
                        {
                            usersInXml = 0;
                        }

                    }
                    reader.ReadEndElement();

                    reader.ReadEndElement();

                    reader.ReadStartElement("Content");
                    z = reader.ReadString();

                    cryptor.GetOpts().EncryptedContent = Convert.FromBase64String(z);
                    reader.ReadEndElement();

                    reader.ReadEndElement();
                    return 0;
                }
                catch (Exception)
                {
                    return 1;
                }
            }
        }

        private void readPrivateKey(string privatePath, string encryptedSessionKey)
        {
            using (XmlReader readerTwo = XmlReader.Create(privatePath))
            {
                readerTwo.ReadStartElement("EncryptedPrivateKey");
                string privKey = readerTwo.ReadString();
                readerTwo.ReadEndElement();

                byte[] encPrivKey = Convert.FromBase64String(privKey);
                CryptOptions optss = new CryptOptions();
                optss.KeySize = 256;
                optss.Mode = 0;
                optss.BlockSize = 128;
                optss.EncryptedContent = encPrivKey;
                optss.ForEncryption = false;

                byte[] pass = System.Text.UTF8Encoding.UTF8.GetBytes(cryptor.GetOpts().Password);
                optss.SessionKey = cryptor.GenerateKeyFromPassword(pass);
                Crypt crypter = new Crypt(optss);
                crypter.Decrypt();
                try
                {
                    RsaKeyParameters privateKey =
                        (RsaKeyParameters)PrivateKeyFactory.CreateKey(crypter.GetOpts().Content);

                    byte[] encrCont = Convert.FromBase64String(encryptedSessionKey);
                    byte[] sessionKey = cryptor.RsaDecrypt(encrCont, privateKey);
                    cryptor.GetOpts().SessionKey = sessionKey;
                }
                catch (Exception) { }
            }
        }

        public byte[] ReadByteArrayFromFile(string fileName)
        {
            byte[] buff = null;
            using (FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                BinaryReader br = new BinaryReader(fs);
                long numBytes = new FileInfo(fileName).Length;
                buff = br.ReadBytes((int)numBytes);
            }
            return buff;
        }

        public bool WriteByteArrayToFile(byte[] buff, string fileName)
        {
            bool response = false;

            try
            {
                using (
                FileStream fs = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite))
                {
                    BinaryWriter bw = new BinaryWriter(fs);
                    bw.Write(buff);
                    bw.Close();
                    response = true;
                }
            }
            catch (Exception)
            {
               
            }

            return response;
        }

        private void button5_Click(object sender, EventArgs e)
        {
            SaveFileDialog dialog2 = new SaveFileDialog();
            dialog2.Title = "Save public key as";
            dialog2.InitialDirectory = @"C:\";
            if (dialog2.ShowDialog() == DialogResult.OK)
            {
                tmpPublic = dialog2.FileName;
            }
            label17.Text = tmpPublic;

        }

        private void button6_Click(object sender, EventArgs e)
        {
            SaveFileDialog dialog2 = new SaveFileDialog();
            dialog2.Title = "Save private key as";
            dialog2.InitialDirectory = @"C:\";
            if (dialog2.ShowDialog() == DialogResult.OK)
            {
                tmpPrivate = dialog2.FileName;
            }
            label18.Text = tmpPrivate;
        }

        private void button7_Click(object sender, EventArgs e)
        {
            String password = textBox2.Text;
            if (password.Length == 0 || label18.Text.Length == 0 || label17.Text.Length == 0)
            {
                MessageBox.Show("Paths or password not specified");
                return;
            }
            names[lines] = textBox1.Text;
            publicKeyPath[lines] = tmpPublic;
            privateKeyPath[lines] = tmpPrivate;
            checkedListBox1.Items.Insert(lines, names[lines]);
            listBox4.Items.Insert(lines, names[lines]);
            lines++;
            AsymmetricCipherKeyPair keys = cryptor.GenerateKeys(512);
            using (StreamWriter writer = new StreamWriter(tmpPublic))
            {
                RsaKeyParameters key = (RsaKeyParameters)keys.Public;
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key);
            	byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
                writer.Write(Convert.ToBase64String(serializedPublicBytes));
            }
            using (XmlWriter writer = XmlWriter.Create(tmpPrivate))
            {
                RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)keys.Private;
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key);
        	    byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded(); 
                CryptOptions optss = new CryptOptions();
                optss.KeySize = 256;
                optss.Mode = 0;
                optss.BlockSize = 128;
                optss.Content = serializedPrivateBytes;
                optss.ForEncryption = true;
                byte[] pass = System.Text.UTF8Encoding.UTF8.GetBytes(password);
                optss.SessionKey = cryptor.GenerateKeyFromPassword(pass);
                Crypt crypter = new Crypt(optss);
                crypter.Encrypt();


                writer.WriteStartDocument();
                writer.WriteStartElement("EncryptedPrivateKey");
                writer.WriteString(Convert.ToBase64String(crypter.GetOpts().EncryptedContent));
                writer.WriteEndElement();
                writer.WriteEndDocument();
            }

            using (StreamWriter writer = new StreamWriter("Resources\\keys.csv", true))
            {
                writer.Write(names[lines - 1]);
                writer.Write(";");
                writer.Write(publicKeyPath[lines - 1]);
                writer.Write(";");
                writer.Write(privateKeyPath[lines - 1]);
                writer.WriteLine();
                writer.Close();
            }
            MessageBox.Show("RSA key pair created");
        }
    }
}