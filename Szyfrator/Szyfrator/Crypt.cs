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
            //opts.SetSessionKey(GenerateSessionKey(opts.GetKeySize()));
            opts.SetInitialVector(GenerateInitialVector());
            byte[] output;
            try
            {
                BufferedBlockCipher cipher = PrepareCipher(true);
                output = ProcessCipher(cipher, opts.GetContent());
            }
            catch (InvalidCipherTextException e)
            {
                BufferedBlockCipher cipher = PrepareCipher(false);
                output = ProcessCipher(cipher, opts.GetContent());
            }
            opts.SetEncryptedContent(output);
        }

        public void Decrypt()
        {
            byte[] output;
		    try 
            {
			    BufferedBlockCipher cipher = PrepareCipher(true);
			    output = ProcessCipher(cipher, opts.GetEncryptedContent());
		    } 
            catch (InvalidCipherTextException e) 
            {
			    // Assuming no use of PKCS
			    BufferedBlockCipher cipher = PrepareCipher(false);
			    output = ProcessCipher(cipher, opts.GetEncryptedContent());
		    }
            opts.SetContent(output);
        }

        public AsymmetricCipherKeyPair GenerateKeys(int keySizeInBits)
	    {
	        RsaKeyPairGenerator r = new RsaKeyPairGenerator();
	        r.Init(new KeyGenerationParameters(new SecureRandom(), keySizeInBits));
	        AsymmetricCipherKeyPair keys = r.GenerateKeyPair();
	        return keys;
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
            /*byte[] outByte = new byte[data.Length];
            for (int i = 0; i < outByte.Length; i++)
            {
                outByte[i] = output.ElementAt(i);
            }
            return outByte;*/
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
            /*byte[] outByte = new byte[data.Length];
            for (int i = 0; i < outByte.Length; i++)
            {
                outByte[i] = output.ElementAt(i);
            }
            return outByte;*/
            return output.ToArray();
        }


        public byte[] GenerateSessionKey(int keySize)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator("RC6");
		    keyGen.Init(new KeyGenerationParameters(new SecureRandom(),keySize));
            return keyGen.GenerateKey();
	    }

	    public byte[] GenerateInitialVector() 
        {
		    // initial vector equals block size
		    Random random = new SecureRandom();
		    byte[] iv = new byte[opts.GetBlockSize()/8];
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
		    switch (opts.GetMode()) 
            {
			    case 0:
				    mode = engine;
				    break;
			    case 1:
				    mode = new CbcBlockCipher(engine);
				    break;
			    case 2:
				    mode = new CfbBlockCipher(engine, opts.GetSubBlockSize());
				    break;
			    case 3:
				    mode = new OfbBlockCipher(engine, opts.GetSubBlockSize());
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

		    KeyParameter keyParameter = new KeyParameter(opts.GetSessionKey());
		    if (opts.GetMode() == 0) 
            {
			    cipher.Init(opts.IsForEncryption(), keyParameter);
		    } 
            else 
            {
			    ParametersWithIV keyAndIVParameter = new ParametersWithIV(keyParameter, opts.GetInitialVector());
			    cipher.Init(opts.IsForEncryption(), keyAndIVParameter);
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
