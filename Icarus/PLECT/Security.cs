using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using System.Runtime.InteropServices;

public class Security
{

    public bool IsAdministrator()
    {
        return Gaia.IsAdministrator();
    }

    //-----------------------------------------------------------------------------------------------------------------------------------------------------------------
    public class Cryptography{
        public class Stream{
            public class Aes{

                public static string AES_encrypt(string plainText, byte[] Key, byte[] IV)
                {
                    return System.Text.Encoding.UTF8.GetString(Frodo.Pipen(plainText, Key, IV));
                }

                public static string AES_decrypt(byte[] cipherText, byte[] Key, byte[] IV)
                {
                    return Frodo.Sam(cipherText, Key, IV);
                }

            }

            public class Base64{

                public static string Base64_decrypt(string encoded_text)
                {
                    return Frodo.Viod(encoded_text);
                }

                public static string Base64_encrypt(string plainText)
                {
                    return Frodo.Voido(plainText);
                }
            }
        }
    }
    
}

protected internal class Gaia
{
    protected internal bool IsAdministrator()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

}


protected internal class Frodo
{
    protected internal static byte[] Pipen(string plainText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");
        byte[] encrypted;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                }

                encrypted = msEncrypt.ToArray();
            }
        }

        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }

    protected internal static string Sam(byte[] cipherText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }

    protected internal static string Viod(string encoded)
    {
        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
    }

    protected internal static string Voido(string plainText)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
    }

}



