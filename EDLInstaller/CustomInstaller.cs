using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Text;

using Microsoft.Win32;

namespace EDLInstaller
{
    [RunInstaller(true)]
    public class CustomInstaller : Installer
    {
        public CustomInstaller() : base() { }

        public override void Commit(System.Collections.IDictionary savedState)
        {
            base.Commit(savedState);
        }

        public override void Install(System.Collections.IDictionary stateSaver)
        {
            base.Install(stateSaver);
            
            /*
            [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\MEDL]
            @="default"
            "ATR"=hex:3b,fa,18,00,00,81,31,fe,45,4a,43,4f,50,34,31,56,32,32,31,9d
            "ATRMask"=hex:ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff
            "Crypto Provider"="Microsoft Base Smart Card Crypto Provider"
            "Smart Card Key Storage Provider"="Microsoft Smart Card Key Storage Provider"
            "80000001"="D:\\MEDL\\svn\\trunk\\EDLMiniDriver\\Debug\\EDLMiniDriver.dll"
           */

            FileInfo fileInfo = new FileInfo(Context.Parameters["assemblyPath"]);
            
            RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\MEDL");
            key.SetValue("ATR", new byte[] { 0x3b, 0xfa, 0x18, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x4a, 0x43, 0x4f, 0x50, 0x34, 0x31, 0x56, 0x32, 0x32, 0x31, 0x9d }, RegistryValueKind.Binary);
            key.SetValue("ATRMask", new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, RegistryValueKind.Binary);
            key.SetValue("Crypto Provider", "Microsoft Base Smart Card Crypto Provider", RegistryValueKind.String);
            key.SetValue("Smart Card Key Storage Provider", "Microsoft Smart Card Key Storage Provider", RegistryValueKind.String);
            key.SetValue("80000001", fileInfo.DirectoryName+@"\EDLMiniDriver.dll", RegistryValueKind.String);

            RegistryKey key2 = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\MEDL2");
            key2.SetValue("ATR", new byte[]     { 0x3b, 0xf4, 0x18, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x4d, 0x45, 0x44, 0x4c, 0xe7 }, RegistryValueKind.Binary);
            key2.SetValue("ATRMask", new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, RegistryValueKind.Binary);
            key2.SetValue("Crypto Provider", "Microsoft Base Smart Card Crypto Provider", RegistryValueKind.String);
            key2.SetValue("Smart Card Key Storage Provider", "Microsoft Smart Card Key Storage Provider", RegistryValueKind.String);
            key2.SetValue("80000001", fileInfo.DirectoryName + @"\EDLMiniDriver.dll", RegistryValueKind.String);
        }

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);

            try
            {
                RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards");
                key.DeleteSubKey("MEDL");
            }
            catch { }
        }

        public override void Rollback(System.Collections.IDictionary savedState)
        {
            base.Rollback(savedState);

            try
            {
                RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards");
                key.DeleteSubKey("MEDL");
            }
            catch { }
        }
    }
}
