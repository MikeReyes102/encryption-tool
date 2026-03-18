# PGPUtility

A simple .NET 8.0 utility for generating, encrypting, and decrypting PGP messages using BouncyCastle.

## Features

- Generate PGP RSA key pairs
- Encrypt messages with a public key
- Decrypt messages with a private key
- Console interface for easy usage

## Project Structure

```
PGPUtility/
  src/
    PGPUtility.Core/      # Core PGP logic (key management, encryption, decryption)
    PGPUtility.Console/   # Console application (user interface)
```

## Getting Started

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download)
- [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) (installed via NuGet)

### Build

From the `PGPUtility` directory:

```sh
dotnet build
```

### Usage

Run the console app:

```sh
dotnet run --project src/PGPUtility.Console
```

#### Commands

- `generate-keys`  
  Generate a new PGP key pair.

- `encrypt`  
  Encrypt a message with a public key.

- `decrypt`  
  Decrypt a message with a private key.

#### Example

```sh
dotnet run --project src/PGPUtility.Console generate-keys
```

Follow the prompts to enter user identity, password, and output paths.

## File Overview

- [`KeyManager`](src/PGPUtility.Core/KeyManager.cs): Key generation and import logic.
- [`Encryptor`](src/PGPUtility.Core/Encryptor.cs): Encrypts messages.
- [`Decryptor`](src/PGPUtility.Core/Decryptor.cs): Decrypts messages.
- [`Program`](src/PGPUtility.Console/Program.cs): Console interface.


