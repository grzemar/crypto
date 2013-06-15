using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;

namespace Szyfrator
{
    public class Crypt
    {
        private Options opts;

	    public Crypt(Options opts) {
		    this.opts = opts;
	    }
        public Options GetOpts()
        {
            return opts;
        }

        public void Encrypt()
        {
            opts.InitialVector = GenerateInitialVector();
            byte[] output;
            try
            {
                BufferedBlockCipher cipher = PrepareCipher(true);
                output = ProcessCipher(cipher, opts.Content);
            }
            catch (InvalidCipherTextException e)
            {
                BufferedBlockCipher cipher = PrepareCipher(false);
                output = ProcessCipher(cipher, opts.Content);
            }
            opts.EncryptedContent = output;
        }

        public void Decrypt()
        {
            byte[] output;
		    try 
            {
			    BufferedBlockCipher cipher = PrepareCipher(true);
			    output = ProcessCipher(cipher, opts.EncryptedContent);
		    } 
            catch (InvalidCipherTextException e) 
            {
			    BufferedBlockCipher cipher = PrepareCipher(false);
			    output = ProcessCipher(cipher, opts.EncryptedContent);
		    }
            opts.Content = output;
        }

        public AsymmetricCipherKeyPair GenerateKeys(int keySizeInBits)
	    {
	        RsaKeyPairGenerator r = new RsaKeyPairGenerator();
	        r.Init(new KeyGenerationParameters(new SecureRandom(), keySizeInBits));
	        AsymmetricCipherKeyPair keys = r.GenerateKeyPair();
	        return keys;
	    }

        public byte[] GenerateSessionKey(int keySize)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator("RC6");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            return keyGen.GenerateKey();
        }


        public byte[] RsaEncrypt(byte[] data, AsymmetricKeyParameter key)
        {
            RsaEngine e = new RsaEngine();
            e.Init(true, key);

            int blockSize = e.GetInputBlockSize();
            List<byte> output = new List<byte>();
            for (int chunkPosition = 0; chunkPosition < data.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - (chunkPosition * blockSize));
                output.AddRange(e.ProcessBlock(data, chunkPosition,chunkSize));
            }
            return output.ToArray();
        }

        public byte[] RsaDecrypt(byte[] data, AsymmetricKeyParameter key)
        {
            RsaEngine e = new RsaEngine();
            e.Init(false, key);

            int blockSize = e.GetInputBlockSize();
            List<byte> output = new List<byte>();
            for (int chunkPosition = 0; chunkPosition < data.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - (chunkPosition * blockSize));
                output.AddRange(e.ProcessBlock(data, chunkPosition, chunkSize));
            }
            return output.ToArray();
        }


    
	    public byte[] GenerateInitialVector() 
        {
		    Random random = new SecureRandom();
		    byte[] iv = new byte[opts.BlockSize/8];
		    random.NextBytes(iv);
		    return iv;
	    }

        public byte[] GenerateKeyFromPassword(byte[] password)
        {
            Sha256Digest digester = new Sha256Digest();
            digester.BlockUpdate(password, 0, password.Length);
            byte[] result = new byte[digester.GetDigestSize()];
            digester.DoFinal(result, 0);
            return result;
        }

        public BufferedBlockCipher PrepareCipher(bool padded)
        {
            IBlockCipher engine = new RC6Engine();
		    IBlockCipher mode;
		    switch (opts.Mode) 
            {
			    case 0:
				    mode = engine;
				    break;
			    case 1:
				    mode = new CbcBlockCipher(engine);
				    break;
			    case 2:
				    mode = new CfbBlockCipher(engine, opts.SubBlockSize);
				    break;
			    case 3:
				    mode = new OfbBlockCipher(engine, opts.SubBlockSize);
				    break;
			    default:
				    mode = engine;
                    break;
		    }

		    BufferedBlockCipher cipher;
		    if (padded) 
            {
			    cipher = new PaddedBufferedBlockCipher(mode);
		    } 
            else 
            {
			    cipher = new BufferedBlockCipher(mode);
		    }

		    KeyParameter keyParameter = new KeyParameter(opts.SessionKey);
		    if (opts.Mode == 0) 
            {
			    cipher.Init(opts.ForEncryption, keyParameter);
		    } 
            else 
            {
			    ParametersWithIV keyAndIVParameter = new ParametersWithIV(keyParameter, opts.InitialVector);
			    cipher.Init(opts.ForEncryption, keyAndIVParameter);
		    }

		    return cipher;
        }

        public byte[] ProcessCipher(BufferedBlockCipher cipher, byte[] input)
        {
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
		    int outputLen = cipher.ProcessBytes(input, 0, input.Length, output, 0);
		    outputLen += cipher.DoFinal(output, outputLen);

		    if (outputLen != output.Length) {
			    byte[] exactOutput = new byte[outputLen];
			    System.Array.Copy(output, 0, exactOutput, 0, outputLen);
			    return exactOutput;
		    }

		    return output;
        }
    }
}
