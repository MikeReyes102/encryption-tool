using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace PGPUtility.Core
{
    public class KeyManager
    {

        /// Generate a new PGP RSA key pair.

        public void GenerateKeyPair(string username, string password, string publicKeyPath, string privateKeyPath)
        {
            const int keySize = 2048; // RSA key size

            // Generate RSA key pair
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            // Create PGP key pair
            PgpKeyPair pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp, DateTime.UtcNow);

            // Setup key ring generator
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                pgpKeyPair,
                username,
                SymmetricKeyAlgorithmTag.Aes256,
                password.ToCharArray(),
                true,
                null,
                null,
                new SecureRandom()
            );

            // Export public key
            using (var pubOut = new StreamWriter(publicKeyPath))
            using (var armoredPubOut = new ArmoredOutputStream(pubOut.BaseStream))
            {
                keyRingGen.GeneratePublicKeyRing().Encode(armoredPubOut);
            }

            // Export private key
            using (var privOut = new StreamWriter(privateKeyPath))
            using (var armoredPrivOut = new ArmoredOutputStream(privOut.BaseStream))
            {
                keyRingGen.GenerateSecretKeyRing().Encode(armoredPrivOut);
            }

            Console.WriteLine("Key pair generated successfully!");
            Console.WriteLine($"Public Key: {publicKeyPath}");
            Console.WriteLine($"Private Key: {privateKeyPath}");
        }


        /// Import a PGP public key from file.
        public PgpPublicKey ImportPublicKey(string path)
        {
            using (Stream keyIn = File.OpenRead(path))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpPublicKeyRingBundle pubRings = new PgpPublicKeyRingBundle(inputStream);
                foreach (PgpPublicKeyRing kRing in pubRings.GetKeyRings())
                {
                    foreach (PgpPublicKey k in kRing.GetPublicKeys())
                    {
                        if (k.IsEncryptionKey)
                            return k;
                    }
                }
            }
            throw new Exception("No encryption key found in public key file.");
        }

        /// Import a PGP private key from file.
        public PgpPrivateKey ImportPrivateKey(string path, string password)
        {
            using (Stream keyIn = File.OpenRead(path))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey secretKey in kRing.GetSecretKeys())
                    {
                        if (secretKey.IsSigningKey || secretKey.IsMasterKey)
                        {
                            return secretKey.ExtractPrivateKey(password.ToCharArray());
                        }
                    }
                }
            }
            throw new Exception("No private key found in file.");
        }
    }
}