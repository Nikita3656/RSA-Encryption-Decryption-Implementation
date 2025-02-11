using System;
using System.Numerics;
using System.Text;

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

        // Example of encryption and decryption
        string message = "Hello, RSA!";
        Console.WriteLine($"\nOriginal Message: {message}");

        // Encrypt the message with the public key
        BigInteger encryptedMessage = Encrypt(message, publicKey);
        Console.WriteLine($"\nEncrypted Message: {encryptedMessage}");

        // Decrypt the message with the private key
        string decryptedMessage = Decrypt(encryptedMessage, privateKey);
        Console.WriteLine($"\nDecrypted Message: {decryptedMessage}");
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

    // Function to encrypt a message using the public key
    public static BigInteger Encrypt(string message, PublicKey publicKey)
    {
        // Convert the message to bytes
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        BigInteger messageInt = new BigInteger(messageBytes);

        // Encrypt the message using the formula: ciphertext = plaintext^e % n
        BigInteger encrypted = BigInteger.ModPow(messageInt, publicKey.e, publicKey.n);
        return encrypted;
    }

    // Function to decrypt a message using the private key
    public static string Decrypt(BigInteger encryptedMessage, PrivateKey privateKey)
    {
        // Decrypt the message using the formula: plaintext = ciphertext^d % n
        BigInteger decryptedInt = BigInteger.ModPow(encryptedMessage, privateKey.d, privateKey.n);

        // Convert the decrypted number back to bytes
        byte[] decryptedBytes = decryptedInt.ToByteArray();
        
        // Convert the bytes back to a string
        string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
        return decryptedMessage;
    }
}
