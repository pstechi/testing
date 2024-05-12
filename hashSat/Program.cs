using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class NativeMethods
{
    public const string BCRYPT_SHA512_ALGORITHM = "SHA512";
    public const int BCRYPT_HASH_LENGTH = 64;
    public const uint BCRYPT_SUCCESS = 0x00000000;

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm,
        string pszAlgId,
        string pszImplementation,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptGetProperty(
        IntPtr hObject,
        string pszProperty,
        [Out] byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptCreateHash(
        IntPtr hAlgorithm,
        out IntPtr phHash,
        IntPtr pbHashObject,
        int cbHashObject,
        byte[] pbSecret,
        int cbSecret,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptHashData(
        IntPtr hHash,
        [In] byte[] pbInput,
        int cbInput,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptFinishHash(
        IntPtr hHash,
        [Out] byte[] pbOutput,
        int cbOutput,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptCloseAlgorithmProvider(
        IntPtr hAlgorithm,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptDestroyHash(
        IntPtr hHash);
}

class Program
{
    static string GenerateSalt()
    {
        // Creating object of random class 
        Random rand = new Random();

        // Define the length of the string (10 characters)
        int stringLength = 10;

        // StringBuilder to build the random string
        StringBuilder builder = new StringBuilder();

        // Loop to generate 10 random characters
        for (int i = 0; i < stringLength; i++)
        {
            // Generating a random number for ASCII characters (65 to 90 for uppercase letters)
            int randValue = rand.Next(65, 91);

            // Generating random character by converting the random number into character
            char letter = Convert.ToChar(randValue);

            // Appending the letter to the string builder
            builder.Append(letter);
        }

        // Convert the StringBuilder to a string
        string randomString = builder.ToString();

        Console.WriteLine("Random String (Salt): " + randomString);

        return randomString;
    }

    //static void StoreValueInRegistry(string keyName, string value)
    //{
    //    RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
    //    RegistryKey subKey = baseKey.CreateSubKey(keyName);

    //    subKey.SetValue("YourValueName", value);
    //    Console.WriteLine("Stored Value in Registry under key: " + keyName);

    //    subKey.Close();
    //}

    //static string RetrieveValueFromRegistry(string keyName)
    //{
    //    RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
    //    RegistryKey subKey = baseKey.OpenSubKey(keyName);

    //    if (subKey != null)
    //    {
    //        string storedValue = subKey.GetValue("YourValueName") as string;
    //        subKey.Close();
    //        return storedValue;
    //    }
    //    else
    //    {
    //        Console.WriteLine("Key not found in the Registry: " + keyName);
    //        return null;
    //    }
    //}

    static void Main()
    {
        IntPtr hAlgorithm = IntPtr.Zero;
        IntPtr hHash = IntPtr.Zero;

        uint status = NativeMethods.BCryptOpenAlgorithmProvider(out hAlgorithm, NativeMethods.BCRYPT_SHA512_ALGORITHM, null, 0);
        if (status != NativeMethods.BCRYPT_SUCCESS)
        {
            throw new CryptographicException("Unable to open algorithm provider. Status code: " + status);
        }

        try
        {
            // Generate Salt
            string salt = GenerateSalt();

            // Hash Input
            string userInput = "QWERTY@!@#";
            byte[] byteInput = Encoding.UTF8.GetBytes(userInput);

            byte[] hash = new byte[NativeMethods.BCRYPT_HASH_LENGTH];

            status = NativeMethods.BCryptCreateHash(hAlgorithm, out hHash, IntPtr.Zero, 0, null, 0, 0);
            if (status != NativeMethods.BCRYPT_SUCCESS)
            {
                throw new CryptographicException("Unable to create hash. Status code: " + status);
            }

            status = NativeMethods.BCryptHashData(hHash, byteInput, byteInput.Length, 0);
            if (status != NativeMethods.BCRYPT_SUCCESS)
            {
                throw new CryptographicException("Unable to hash data. Status code: " + status);
            }

            status = NativeMethods.BCryptFinishHash(hHash, hash, hash.Length, 0);
            if (status != NativeMethods.BCRYPT_SUCCESS)
            {
                throw new CryptographicException("Unable to finalize hash. Status code: " + status);
            }

            Console.WriteLine("Hashed Output: " + BitConverter.ToString(hash).Replace("-", ""));
            Console.WriteLine("Hashed Output with salt: " + (BitConverter.ToString(hash).Replace("-", "")) + salt);
            Console.WriteLine("Salt: " + salt);

            string combinedHash = BitConverter.ToString(hash).Replace("-", "") + salt;

           // string subkey = @"SOFTWARE\AppName\AppVersion";

            //StoreValueInRegistry(subkey, combinedHash);
            //string retrievedValue = RetrieveValueFromRegistry(subkey);

            //if (!string.IsNullOrEmpty(retrievedValue))
            //{
            //    Console.WriteLine("Retrieved Value from Registry: " + retrievedValue);

            //    // Splitting the retrieved value into hash and salt
            //    if (retrievedValue.Length >= 64)
            //    {
            //        string storedHash = retrievedValue.Substring(0, 64);
            //        string storedSalt = retrievedValue.Substring(64);

            //        Console.WriteLine("Retrieved Hash: " + storedHash);
            //        Console.WriteLine("Retrieved Salt: " + storedSalt);
            //    }
            //    else
            //    {
            //        Console.WriteLine("Invalid stored value format.");
            //    }
            //}
        }
        finally
        {
            if (hHash != IntPtr.Zero)
            {
                NativeMethods.BCryptDestroyHash(hHash);
            }

            if (hAlgorithm != IntPtr.Zero)
            {
                NativeMethods.BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            }
        }
    }
}