using System;
using PGPUtility.Core;

class Program
{
    static void Main(string[] args)
    {
        var keyManager = new KeyManager();

        if (args.Length == 0)
        {
            ShowHelp();
            return;
        }

        switch (args[0].ToLower())
        {
            case "generate-keys":
                GenerateKeys(keyManager);
                break;

            case "encrypt":
                EncryptMessage();
                break;

            case "decrypt":
                DecryptMessage();
                break;

            default:
                Console.WriteLine("Unknown command.");
                ShowHelp();
                break;
        }
    }

    static void GenerateKeys(KeyManager keyManager)
    {
        Console.Write("User Identity (Name <email>): ");
        string user = Console.ReadLine() ?? "";

        Console.Write("Password (optional): ");
        string password = Console.ReadLine() ?? "";

        Console.Write("Public key output path: ");
        string pubPath = Console.ReadLine() ?? "";

        Console.Write("Private key output path: ");
        string privPath = Console.ReadLine() ?? "";

        keyManager.GenerateKeyPair(user, password, pubPath, privPath);
    }

    static void EncryptMessage()
    {
        var encryptor = new PGPUtility.Core.Encryptor();

        Console.Write("Message to encrypt: ");
        string message = Console.ReadLine() ?? "";

        Console.Write("Public key path: ");
        string keyPath = Console.ReadLine() ?? "";

        Console.Write("Output file (leave blank to print to console): ");
        string outputPath = Console.ReadLine() ?? "";

        string encrypted = encryptor.EncryptString(message, keyPath);

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.WriteLine("\nEncrypted Message:\n");
            Console.WriteLine(encrypted);
        }
        else
        {
            File.WriteAllText(outputPath, encrypted);
            Console.WriteLine($"\nEncrypted message saved to: {outputPath}");
        }
    }

    static void DecryptMessage()
    {
        var decryptor = new PGPUtility.Core.Decryptor();

        Console.Write("Encrypted message file path: ");
        string inputPath = Console.ReadLine() ?? "";

        Console.Write("Private key path: ");
        string privateKeyPath = Console.ReadLine() ?? "";

        Console.Write("Private key password: ");
        string password = Console.ReadLine() ?? "";

        string encryptedMessage = File.ReadAllText(inputPath);

        string decrypted = decryptor.DecryptString(encryptedMessage, privateKeyPath, password);

        Console.WriteLine("\nDecrypted Message:\n");
        Console.WriteLine(decrypted);
    }

    static void ShowHelp()
    {
        Console.WriteLine("PGP Utility");
        Console.WriteLine("----------------------");
        Console.WriteLine("Commands:");
        Console.WriteLine("generate-keys   Generate a new PGP key pair");
    }
}