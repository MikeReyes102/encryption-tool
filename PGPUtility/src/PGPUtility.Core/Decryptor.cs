using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

namespace PGPUtility.Core
{
    public class Decryptor
    {
        public string DecryptString(string encryptedMessage, string privateKeyPath, string password)
        {
            var keyManager = new KeyManager();

            PgpPrivateKey privateKey = keyManager.ImportPrivateKey(privateKeyPath, password);

            using MemoryStream encryptedStream = new MemoryStream(Encoding.UTF8.GetBytes(encryptedMessage));
            using Stream decoderStream = PgpUtilities.GetDecoderStream(encryptedStream);

            PgpObjectFactory pgpFactory = new PgpObjectFactory(decoderStream);

            PgpEncryptedDataList encList;

            object obj = pgpFactory.NextPgpObject();

            if (obj is PgpEncryptedDataList)
                encList = (PgpEncryptedDataList)obj;
            else
                encList = (PgpEncryptedDataList)pgpFactory.NextPgpObject();

            PgpPublicKeyEncryptedData? encryptedData = null;

            foreach (PgpPublicKeyEncryptedData pked in encList.GetEncryptedDataObjects())
            {
                encryptedData = pked;
                break;
            }

            using Stream clearStream = encryptedData.GetDataStream(privateKey);

            PgpObjectFactory plainFact = new PgpObjectFactory(clearStream);

            object message = plainFact.NextPgpObject();

            if (message is PgpCompressedData compressedData)
            {
                Stream compDataIn = compressedData.GetDataStream();
                PgpObjectFactory compressedFactory = new PgpObjectFactory(compDataIn);
                message = compressedFactory.NextPgpObject();
            }

            PgpLiteralData literalData = (PgpLiteralData)message;

            using Stream unc = literalData.GetInputStream();
            using StreamReader reader = new StreamReader(unc, Encoding.UTF8);

            return reader.ReadToEnd();
        }
    }
}