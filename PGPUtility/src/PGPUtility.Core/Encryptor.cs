using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace PGPUtility.Core
{
    public class Encryptor
    {
        public string EncryptString(string message, string publicKeyPath)
        {
            var keyManager = new KeyManager();
            PgpPublicKey encKey = keyManager.ImportPublicKey(publicKeyPath);

            byte[] data = Encoding.UTF8.GetBytes(message);

            using MemoryStream outputStream = new MemoryStream();

            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
            {
                PgpEncryptedDataGenerator encGen =
                    new PgpEncryptedDataGenerator(
                        SymmetricKeyAlgorithmTag.Aes256,
                        true,
                        new SecureRandom());

                encGen.AddMethod(encKey);

                using Stream encryptedOut = encGen.Open(armoredStream, new byte[1 << 16]);

                // compression layer
                PgpCompressedDataGenerator comData =
                    new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);

                using Stream compressedOut = comData.Open(encryptedOut);

                // literal data layer
                PgpLiteralDataGenerator literalData = new PgpLiteralDataGenerator();

                using Stream literalOut = literalData.Open(
                    compressedOut,
                    PgpLiteralData.Binary,
                    "message",
                    data.Length,
                    DateTime.UtcNow);

                literalOut.Write(data, 0, data.Length);
            }

            return Encoding.UTF8.GetString(outputStream.ToArray());
        }
    }
}