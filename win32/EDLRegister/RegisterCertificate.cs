using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EDLRegister
{
    public class CertificateContext
    {
        public string containerName;
        public string providerName;
        public uint keySpec;

        public CertificateContext(string containerName, string providerName, uint keySpec)
        {
            this.containerName = containerName;
            this.providerName = providerName;
            this.keySpec = keySpec;
        }
    }

    public class RegisterCertificate
    {
        #region interop helpers

        // exported key blob definitions
        public const uint SIMPLEBLOB = 0x1;
        public const uint PUBLICKEYBLOB = 0x6;
        public const uint PRIVATEKEYBLOB = 0x7;
        public const uint PLAINTEXTKEYBLOB = 0x8;

        public const uint AT_KEYEXCHANGE = 1;
        public const uint AT_SIGNATURE = 2;

        public const uint CRYPT_USERDATA = 1;

        // dwParam
        public const uint KP_IV = 1;       // Initialization vector
        public const uint KP_SALT = 2;       // Salt value
        public const uint KP_PADDING = 3;       // Padding values
        public const uint KP_MODE = 4;       // Mode of the cipher
        public const uint KP_MODE_BITS = 5;       // Number of bits to feedback
        public const uint KP_PERMISSIONS = 6;       // Key permissions DWORD
        public const uint KP_ALGID = 7;       // Key algorithm
        public const uint KP_BLOCKLEN = 8;       // Block size of the cipher
        public const uint KP_KEYLEN = 9;       // Length of key in bits
        public const uint KP_SALT_EX = 10;      // Length of salt in bytes
        public const uint KP_P = 11;      // DSS/Diffie-Hellman P value
        public const uint KP_G = 12;      // DSS/Diffie-Hellman G value
        public const uint KP_Q = 13;      // DSS Q value
        public const uint KP_X = 14;      // Diffie-Hellman X value
        public const uint KP_Y = 15;      // Y value
        public const uint KP_RA = 16;      // Fortezza RA value
        public const uint KP_RB = 17;      // Fortezza RB value
        public const uint KP_INFO = 18;      // for putting information into an RSA envelope
        public const uint KP_EFFECTIVE_KEYLEN = 19;      // setting and getting RC2 effective key length
        public const uint KP_SCHANNEL_ALG = 20;      // for setting the Secure Channel algorithms
        public const uint KP_CLIENT_RANDOM = 21;      // for setting the Secure Channel client random data
        public const uint KP_SERVER_RANDOM = 22;      // for setting the Secure Channel server random data
        public const uint KP_RP = 23;
        public const uint KP_PRECOMP_MD5 = 24;
        public const uint KP_PRECOMP_SHA = 25;
        public const uint KP_CERTIFICATE = 26;      // for setting Secure Channel certificate data (PCT1)
        public const uint KP_CLEAR_KEY = 27;     // for setting Secure Channel clear key data (PCT1)
        public const uint KP_PUB_EX_LEN = 28;
        public const uint KP_PUB_EX_VAL = 29;

        //
        // CryptGetProvParam
        //
        public const uint PP_ENUMALGS = 1;
        public const uint PP_ENUMCONTAINERS = 2;
        public const uint PP_IMPTYPE = 3;
        public const uint PP_NAME = 4;
        public const uint PP_VERSION = 5;
        public const uint PP_CONTAINER = 6;
        public const uint PP_CHANGE_PASSWORD = 7;
        public const uint PP_KEYSET_SEC_DESCR = 8;      // get/set security descriptor of keyset
        public const uint PP_CERTCHAIN = 9;     // for retrieving certificates from tokens
        public const uint PP_KEY_TYPE_SUBTYPE = 10;
        public const uint PP_PROVTYPE = 16;
        public const uint PP_KEYSTORAGE = 17;
        public const uint PP_APPLI_CERT = 18;
        public const uint PP_SYM_KEYSIZE = 19;
        public const uint PP_SESSION_KEYSIZE = 20;
        public const uint PP_UI_PROMPT = 21;
        public const uint PP_ENUMALGS_EX = 22;

        public const uint CRYPT_FIRST = 1;
        public const uint CRYPT_NEXT = 2;

        public const uint CRYPT_IMPL_HARDWARE = 1;
        public const uint CRYPT_IMPL_SOFTWARE = 2;
        public const uint CRYPT_IMPL_MIXED = 3;
        public const uint CRYPT_IMPL_UNKNOWN = 4;

        //
        // CryptSetProvParam
        //
        public const uint PP_CLIENT_HWND = 1;
        public const uint PP_CONTEXT_INFO = 11;
        public const uint PP_KEYEXCHANGE_KEYSIZE = 12;
        public const uint PP_SIGNATURE_KEYSIZE = 13;
        public const uint PP_KEYEXCHANGE_ALG = 14;
        public const uint PP_SIGNATURE_ALG = 15;
        public const uint PP_DELETEKEY = 24;

        public const uint PROV_RSA_FULL = 1;
        public const uint PROV_RSA_SIG = 2;
        public const uint PROV_DSS = 3;
        public const uint PROV_FORTEZZA = 4;
        public const uint PROV_MS_EXCHANGE = 5;
        public const uint PROV_SSL = 6;
        public const uint PROV_RSA_SCHANNEL = 12;
        public const uint PROV_DSS_DH = 13;
        public const uint PROV_EC_ECDSA_SIG = 14;
        public const uint PROV_EC_ECNRA_SIG = 15;
        public const uint PROV_EC_ECDSA_FULL = 16;
        public const uint PROV_EC_ECNRA_FULL = 17;
        public const uint PROV_SPYRUS_LYNKS = 20;

        //  Certificate and Message encoding types
        public const uint CRYPT_ASN_ENCODING = 0x00000001;
        public const uint CRYPT_NDR_ENCODING = 0x00000002;
        public const uint X509_ASN_ENCODING = 0x00000001;
        public const uint X509_NDR_ENCODING = 0x00000002;
        public const uint PKCS_7_ASN_ENCODING = 0x00010000;
        public const uint PKCS_7_NDR_ENCODING = 0x00020000;

        //  Certificate, CRL and CTL property IDs
        public const uint CERT_KEY_PROV_HANDLE_PROP_ID = 1;
        public const uint CERT_KEY_PROV_INFO_PROP_ID = 2;
        public const uint CERT_SHA1_HASH_PROP_ID = 3;
        public const uint CERT_MD5_HASH_PROP_ID = 4;
        public const uint CERT_HASH_PROP_ID = CERT_SHA1_HASH_PROP_ID;
        public const uint CERT_KEY_CONTEXT_PROP_ID = 5;
        public const uint CERT_KEY_SPEC_PROP_ID = 6;
        public const uint CERT_IE30_RESERVED_PROP_ID = 7;
        public const uint CERT_PUBKEY_HASH_RESERVED_PROP_ID = 8;
        public const uint CERT_ENHKEY_USAGE_PROP_ID = 9;
        public const uint CERT_CTL_USAGE_PROP_ID = CERT_ENHKEY_USAGE_PROP_ID;
        public const uint CERT_NEXT_UPDATE_LOCATION_PROP_ID = 10;
        public const uint CERT_FRIENDLY_NAME_PROP_ID = 11;
        public const uint CERT_PVK_FILE_PROP_ID = 12;
        // Note, 32 - 34 are reserved for the CERT, CRL and CTL file element IDs.
        public const uint CERT_FIRST_RESERVED_PROP_ID = 13;

        public const uint CERT_LAST_RESERVED_PROP_ID = 0x00007FFF;
        public const uint CERT_FIRST_USER_PROP_ID = 0x00008000;
        public const uint CERT_LAST_USER_PROP_ID = 0x0000FFFF;

        //  Certificate Store Provider Types
        public const uint CERT_STORE_PROV_MSG = 1;

        public const uint CERT_STORE_PROV_MEMORY = 2;
        public const uint CERT_STORE_PROV_FILE = 3;
        public const uint CERT_STORE_PROV_REG = 4;

        public const uint CERT_STORE_PROV_PKCS7 = 5;
        public const uint CERT_STORE_PROV_SERIALIZED = 6;
        public const uint CERT_STORE_PROV_FILENAME_A = 7;
        public const uint CERT_STORE_PROV_FILENAME_W = 8;
        public const uint CERT_STORE_PROV_FILENAME = CERT_STORE_PROV_FILENAME_W;
        public const uint CERT_STORE_PROV_SYSTEM_A = 9;
        public const uint CERT_STORE_PROV_SYSTEM_W = 10;
        public const uint CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W;

        public const string sz_CERT_STORE_PROV_MEMORY = "Memory";
        public const string sz_CERT_STORE_PROV_FILENAME_W = "File";
        public const string sz_CERT_STORE_PROV_FILENAME = sz_CERT_STORE_PROV_FILENAME_W;
        public const string sz_CERT_STORE_PROV_SYSTEM_W = "System";
        public const string sz_CERT_STORE_PROV_SYSTEM = sz_CERT_STORE_PROV_SYSTEM_W;
        public const string sz_CERT_STORE_PROV_PKCS7 = "PKCS7";
        public const string sz_CERT_STORE_PROV_SERIALIZED = "Serialized";

        // Location of the system store in the registry:
        public const uint CERT_SYSTEM_STORE_LOCATION_MASK = 0x00030000;
        public const uint CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
        public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;
        public const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;

        // Add certificate/CRL, encoded, context or element disposition values.
        public const uint CERT_STORE_ADD_NEW = 1;
        public const uint CERT_STORE_ADD_USE_EXISTING = 2;
        public const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
        public const uint CERT_STORE_ADD_ALWAYS = 4;

        // dwFlags definitions for CryptAcquireContext
        public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        public const uint CRYPT_NEWKEYSET = 0x00000008;
        public const uint CRYPT_DELETEKEYSET = 0x00000010;
        public const uint CRYPT_MACHINE_KEYSET = 0x00000020;

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string ContainerName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string ProvName;

            public uint ProvType;
            public uint Flags;
            public uint ProvParam;
            public IntPtr rgProvParam;
            public uint KeySpec;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData, ref uint dwDataLen, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, [In, Out] byte[] pbData, ref uint dwDataLen, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetUserKey(IntPtr hProv, uint dwKeySpec, ref IntPtr hKey);

        [DllImport("advapi32.dll")]
        public static extern bool CryptGetKeyParam(IntPtr hKey, uint dwParam, uint prop, ref uint dwDataLen, uint dwFlags);

        [DllImport("ADVAPI32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptGetKeyParam(IntPtr hKey, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);

        //[DllImport("Crypt32.DLL", EntryPoint = "CertCreateCertificateContext",SetLastError = true,CharSet = CharSet.Unicode, ExactSpelling = false,CallingConvention = CallingConvention.StdCall)]
        [DllImport("Crypt32.DLL", SetLastError = true)]
        private static extern IntPtr CertCreateCertificateContext(uint dwCertEncodingType, byte[] pbCertEncoded, uint cbCertEncoded);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertSetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, uint dwFlags, IntPtr pvData);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertSetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, uint dwFlags, ref CRYPT_KEY_PROV_INFO pvData);

        [DllImport("CRYPT32.DLL", EntryPoint = "CertOpenStore", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenStoreStringPara(uint storeProvider, int encodingType, IntPtr hcryptProv, uint flags, String pvPara);

        [DllImport("CRYPT32.DLL", EntryPoint = "CertOpenStore", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenStoreIntPtrPara(uint storeProvider, int encodingType, IntPtr hcryptProv, int flags, IntPtr pvPara);

        [DllImport(@"crypt32.dll", SetLastError = true)]
        internal static extern bool CertAddCertificateContextToStore(IntPtr hCertStore, IntPtr pCertContext, uint dwAddDisposition, IntPtr ppStoreContext);

        [DllImport(@"advapi32.dll", SetLastError = true)]
        public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [DllImport(@"advapi32.dll", SetLastError = true)]
        public static extern bool CryptDestroyKey(IntPtr phKey);

        #endregion interop helpers

        public class CertItem
        {
            public X509Certificate2 cert;
            public CertificateContext context;

            public CertItem(X509Certificate2 cert, CertificateContext context)
            {
                this.cert = cert;
                this.context = context;
            }
        }

        //public static Dictionary<X509Certificate2, CertificateContext> GetCertificates()
        public static List<CertItem> GetCertificates()
        {
            //Dictionary<X509Certificate2, CertificateContext> result = new Dictionary<X509Certificate2, CertificateContext>();
            List<CertItem> result = new List<CertItem>();

            //foreach (KeyValuePair<byte[], CertificateContext> rawCert in GetRawCertificates())
            //    result.Add(new X509Certificate2(rawCert.Key), rawCert.Value);
            foreach (RawCert rawCert in GetRawCertificates())
                result.Add(new CertItem(new X509Certificate2(rawCert.bytes), rawCert.context));
            
            return result;
        }

        public class RawCert
        {
            public byte[] bytes;
            public CertificateContext context;

            public RawCert(byte[] bytes, CertificateContext context)
            {
                this.bytes = bytes;
                this.context = context;
            }
        }

        //public static Dictionary<byte[], CertificateContext> GetRawCertificates()
        public static List<RawCert> GetRawCertificates()
        {
            //Dictionary<byte[], CertificateContext> result = new Dictionary<byte[], CertificateContext>();
            List<RawCert> result = new List<RawCert>();
            
            uint[] keySpecs = { AT_SIGNATURE, AT_KEYEXCHANGE };
            string providerName = "Microsoft Base Smart Card Crypto Provider";
            IntPtr hMainCryptProvider = new IntPtr();
            
            /*if (!CryptAcquireContext(ref hCryptProvider, null, providerName, PROV_RSA_FULL, (uint)0))
                throw new RegisterException(new RegisterExceptionEventArgs(RegisterException.ACQUIRE_CONTEXT));*/
            if (!CryptAcquireContext(ref hMainCryptProvider, null, providerName, PROV_RSA_FULL,(uint) 0))
                throw new RegisterException(new RegisterExceptionEventArgs(RegisterException.ACQUIRE_CONTEXT));
            
            uint bufferSize = 1024;
            StringBuilder containerName = new StringBuilder((int)bufferSize);

            uint dwFlags = CRYPT_FIRST;
            // enumerate all containers
            while (CryptGetProvParam(hMainCryptProvider, PP_ENUMCONTAINERS, containerName, ref bufferSize, dwFlags))
            {
                Debug.WriteLine("Container Name: " + containerName.ToString());
                IntPtr hCryptProvider = new IntPtr();
                if (!CryptAcquireContext(ref hCryptProvider, containerName.ToString(), providerName, PROV_RSA_FULL, 0))
                    continue;

                // loop over the key specs
                foreach (uint keySpec in keySpecs)
                {
                    IntPtr hUserKey = new IntPtr();
                    uint certLen = 0;

                    if (!CryptGetUserKey(hCryptProvider, keySpec, ref hUserKey))
                        continue;

                    if (!CryptGetKeyParam(hUserKey, KP_CERTIFICATE, 0, ref certLen, 0)) // get certificate length
                        throw new Exception("Could not retrieve certificate length.");

                    Debug.WriteLine("got certificate length");

                    byte[] rawCert = new byte[certLen];
                    if (!CryptGetKeyParam(hUserKey, KP_CERTIFICATE, rawCert, ref certLen, 0)) // get certificate
                        throw new Exception("Could not retrieve certificate.");

                    //result.Add(rawCert, new CertificateContext(containerName.ToString(), providerName,keySpec));
                    result.Add( new RawCert(rawCert, new CertificateContext(containerName.ToString(), providerName, keySpec)));
                    Debug.WriteLine("got certificate");

                    CryptDestroyKey(hUserKey);
                }

                CryptReleaseContext(hCryptProvider, 0);

                // prepare parameters for the next loop
                bufferSize = 1024;
                dwFlags = CRYPT_NEXT;
            }
            CryptReleaseContext(hMainCryptProvider, 0);
            return result;
        }

        public static void Register(X509Certificate2 cert, CertificateContext context)
        {
            IntPtr hCertContext = new IntPtr();
            hCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert.RawData,(uint) cert.RawData.Length);

            CRYPT_KEY_PROV_INFO ProvInfo = new CRYPT_KEY_PROV_INFO();
            ProvInfo.ContainerName = context.containerName;
            ProvInfo.ProvName = context.providerName;
            ProvInfo.ProvType = PROV_RSA_FULL;
            ProvInfo.Flags = 0;
            ProvInfo.KeySpec = context.keySpec;
            ProvInfo.ProvParam = 0;
            ProvInfo.rgProvParam = new IntPtr();

            if (!CertSetCertificateContextProperty(hCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, ref ProvInfo))
                throw new Exception("Could set certificate's context.");

            Debug.WriteLine("Context set!");

            IntPtr hCertStore = CertOpenStoreStringPara(CERT_STORE_PROV_SYSTEM_W, 0, new IntPtr(),
                CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, "My");

            if (!CertAddCertificateContextToStore(hCertStore, hCertContext, CERT_STORE_ADD_REPLACE_EXISTING, new IntPtr()))
                throw new Exception("Could not add certificate to store.");
        }

        public static void RegisterKeyContainer()
        {
            uint[] keySpecs = { AT_SIGNATURE, AT_KEYEXCHANGE };
            string providerName = "Microsoft Base Smart Card Crypto Provider";
            IntPtr hCryptProvider = new IntPtr();
            
            if (!CryptAcquireContext(ref hCryptProvider, null, providerName, PROV_RSA_FULL, (uint)0))
                throw new RegisterException(new RegisterExceptionEventArgs(RegisterException.ACQUIRE_CONTEXT));
            
            uint bufferSize = 1024;
            StringBuilder containerName = new StringBuilder((int)bufferSize);

            // enumerate all containers
            while (CryptGetProvParam(hCryptProvider, PP_ENUMCONTAINERS, containerName, ref bufferSize, CRYPT_FIRST))
            {
                Debug.WriteLine("Container Name: " + containerName.ToString());
                if (!CryptAcquireContext(ref hCryptProvider, containerName.ToString(), providerName, PROV_RSA_FULL, 0))
                    continue;

                // loop over the key specs
                foreach (uint keySpec in keySpecs)
                {
                    IntPtr hUserKey = new IntPtr();
                    uint certLen = 0;

                    if (!CryptGetUserKey(hCryptProvider, keySpec, ref hUserKey))
                        continue;
                    
                    if (!CryptGetKeyParam(hUserKey, KP_CERTIFICATE, 0, ref certLen, 0)) // get certificate length
                        throw new Exception("Could not retrieve certificate length.");
                    
                    Debug.WriteLine("got certificate length");

                    byte[] rawCert = new byte[certLen];
                    if (!CryptGetKeyParam(hUserKey, KP_CERTIFICATE, rawCert, ref certLen, 0)) // get certificate
                        throw new Exception("Could not retrieve certificate.");
                    
                    Debug.WriteLine("got certificate");
                    IntPtr hCertContext = new IntPtr();
                    hCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, rawCert, certLen);

                    CRYPT_KEY_PROV_INFO ProvInfo = new CRYPT_KEY_PROV_INFO();
                    ProvInfo.ContainerName = containerName.ToString();
                    ProvInfo.ProvName = providerName;
                    ProvInfo.ProvType = PROV_RSA_FULL;
                    ProvInfo.Flags = 0;
                    ProvInfo.KeySpec = AT_SIGNATURE;
                    ProvInfo.ProvParam = 0;
                    ProvInfo.rgProvParam = new IntPtr();

                    X509Certificate2 c = new X509Certificate2(rawCert);
                    string name = c.SubjectName.Name;

                    if (!CertSetCertificateContextProperty(hCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, ref ProvInfo))
                        throw new Exception("Could set certificate's context.");
                    
                    Debug.WriteLine("Context set!");

                    IntPtr hCertStore = CertOpenStoreStringPara(CERT_STORE_PROV_SYSTEM_W, 0, new IntPtr(),
                        CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, "My");

                    if (!CertAddCertificateContextToStore(hCertStore, hCertContext, CERT_STORE_ADD_REPLACE_EXISTING, new IntPtr()))
                        throw new Exception("Could not add certificate to store.");
                }
            }
        }
    }
}
