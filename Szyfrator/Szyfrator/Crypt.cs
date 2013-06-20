using System;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto;
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
        private CryptOptions options;

	    public Crypt(CryptOptions opts) {
		    this.options = opts;
	    }
        public CryptOptions GetOpts()
        {
            return options;
        }

        public void Encrypt()
        {
            options.InitialVector = GenerateInitialVector();
            byte[] output;
            try
            {
                BufferedBlockCipher cipher = SetCipherOptions(true);
                output = PerformCipherOperations(cipher, options.Content);
            }
            catch (InvalidCipherTextException)
            {
                BufferedBlockCipher cipher = SetCipherOptions(false);
                output = PerformCipherOperations(cipher, options.Content);
            }
            options.EncryptedContent = output;
        }

        public void Decrypt()
        {
            byte[] output;
		    try 
            {
			    BufferedBlockCipher cipher = SetCipherOptions(true);
			    output = PerformCipherOperations(cipher, options.EncryptedContent);
		    } 
            catch (InvalidCipherTextException) 
            {
			    BufferedBlockCipher cipher = SetCipherOptions(false);
			    output = PerformCipherOperations(cipher, options.EncryptedContent);
		    }
            options.Content = output;
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
		    byte[] iv = new byte[options.BlockSize/8];
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

        public BufferedBlockCipher SetCipherOptions(bool padded)
        {
            IBlockCipher engine = new RC6Engine();
		    IBlockCipher mode;
		    switch (options.Mode) 
            {
			    case 0:
				    mode = engine;
				    break;
			    case 1:
				    mode = new CbcBlockCipher(engine);
				    break;
			    case 2:
				    mode = new CfbBlockCipher(engine, options.SubBlockSize);
				    break;
			    case 3:
				    mode = new OfbBlockCipher(engine, options.SubBlockSize);
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

		    KeyParameter keyParameter = new KeyParameter(options.SessionKey);
		    if (options.Mode == 0) 
            {
			    cipher.Init(options.ForEncryption, keyParameter);
		    } 
            else 
            {
			    ParametersWithIV keyAndIVParameter = new ParametersWithIV(keyParameter, options.InitialVector);
			    cipher.Init(options.ForEncryption, keyAndIVParameter);
		    }

		    return cipher;
        }

        public byte[] PerformCipherOperations(BufferedBlockCipher cipher, byte[] input)
        {
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
		    int outputLength = cipher.ProcessBytes(input, 0, input.Length, output, 0);
		    outputLength += cipher.DoFinal(output, outputLength);

		    if (outputLength != output.Length) {
			    byte[] finalOutput = new byte[outputLength];
			    System.Array.Copy(output, 0, finalOutput, 0, outputLength);
			    return finalOutput;
		    }

		    return output;
        }
    }
}
