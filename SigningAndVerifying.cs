using System;
using System.Numerics;
using System.Text;
using System.Security.Cryptography;

class RSA
{
    public static void Main()
    {
        // Generate RSA keys
        var (publicKey, privateKey) = GenerateKeys();

        Console.WriteLine("Public Key: ");
        Console.WriteLine($"n: {publicKey.n}, e: {publicKey.e}");

        Console.WriteLine("Private Key: ");
        Console.WriteLine($"n: {privateKey.n}, d: {privateKey.d}");

        // Original message
        string message = "Hello, RSA! This is a message with integrity check.";

        // Sign the message with the private key
        BigInteger signature = SignMessage(message, privateKey);
        Console.WriteLine($"\nDigital Signature: {signature}");

        // Verify the signature with the public key
        bool isVerified = VerifySignature(message, signature, publicKey);
        Console.WriteLine($"\nSignature Verified: {isVerified}");
    }

    // Structure to store the public key
    public struct PublicKey
    {
        public BigInteger n;
        public BigInteger e;
    }

    // Structure to store the private key
    public struct PrivateKey
    {
        public BigInteger n;
        public BigInteger d;
    }

    // Function to generate RSA keys (public and private)
    public static (PublicKey, PrivateKey) GenerateKeys()
    {
        // Step 1: Generate two large prime numbers p and q
        BigInteger p = GeneratePrime();
        BigInteger q = GeneratePrime();

        // Step 2: Calculate n = p * q
        BigInteger n = p * q;

        // Step 3: Calculate Euler's totient function φ(n) = (p-1) * (q-1)
        BigInteger phi = (p - 1) * (q - 1);

        // Step 4: Choose a public exponent e (common choices are 3, 65537)
        BigInteger e = 65537;

        // Step 5: Calculate the private exponent d such that (d * e) % φ(n) = 1
        BigInteger d = ModInverse(e, phi);

        // Return the public and private keys
        return (new PublicKey { n = n, e = e }, new PrivateKey { n = n, d = d });
    }

    // Function to generate a random prime number (for simplicity, returns small primes)
    public static BigInteger GeneratePrime()
    {
        // In practice, you would use a large prime generation method
        return new BigInteger(new byte[] { 61 });
    }

    // Function to compute modular inverse using Extended Euclidean Algorithm
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger t = 0;
        BigInteger newT = 1;
        BigInteger r = m;
        BigInteger newR = a;

        while (newR != 0)
        {
            BigInteger quotient = r / newR;

            BigInteger tempT = t;
            t = newT;
            newT = tempT - quotient * newT;

            BigInteger tempR = r;
            r = newR;
            newR = tempR - quotient * newR;
        }

        if (r > 1)
        {
            throw new Exception("No modular inverse exists.");
        }

        if (t < 0)
        {
            t = t + m;
        }

        return t;
    }

    // Function to sign a message using the private key
    public static BigInteger SignMessage(string message, PrivateKey privateKey)
    {
        // Hash the message (using SHA-256)
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] hashedMessage = SHA256.Create().ComputeHash(messageBytes);

        // Convert the hash to a BigInteger
        BigInteger messageHash = new BigInteger(hashedMessage);

        // Sign the hash with the private key: signature = hash^d % n
        BigInteger signature = BigInteger.ModPow(messageHash, privateKey.d, privateKey.n);
        return signature;
    }

    // Function to verify a message signature using the public key
    public static bool VerifySignature(string message, BigInteger signature, PublicKey publicKey)
    {
        // Hash the original message (using SHA-256)
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] hashedMessage = SHA256.Create().ComputeHash(messageBytes);

        // Convert the hash to a BigInteger
        BigInteger originalMessageHash = new BigInteger(hashedMessage);

        // Decrypt the signature with the public key: decrypted = signature^e % n
        BigInteger decryptedSignature = BigInteger.ModPow(signature, publicKey.e, publicKey.n);

        // If the decrypted signature matches the original message hash, the signature is valid
        return originalMessageHash == decryptedSignature;
    }
}
