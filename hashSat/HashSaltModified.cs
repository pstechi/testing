//using System;
//using System.Runtime.InteropServices;
//using System.Security.Cryptography;
//using System.Text;

//namespace hashSat
//{
//    class NativeMethods
//    {
//        public const string BCRYPT_SHA512_ALGORITHM = "SHA512";
//        public const int BCRYPT_HASH_LENGTH = 64;
//        public const uint BCRYPT_SUCCESS = 0x00000000;

//        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
//        public static extern uint BCryptOpenAlgorithmProvider(
//            out IntPtr phAlgorithm,
//            string pszAlgId,
//            string pszImplementation,
//            uint dwFlags);

//        [DllImport("bcrypt.dll")]
//        public static extern uint BCryptGetProperty(
//            IntPtr hObject,
//            string pszProperty,
//            [Out] byte[] pbOutput,
//            int cbOutput,
//            out int pcbResult,
//            uint dwFlags);

//        [DllImport("bcrypt.dll")]
//        public static extern uint BCryptCreateHash(
//            IntPtr hAlgorithm,
//            out IntPtr phHash,
//            IntPtr pbHashObject,
//            int cbHashObject,
//            byte[] pbSecret,
//            int cbSecret,
//            uint dwFlags);

//        [DllImport("bcrypt.dll")]
//        public static extern uint BCryptHashData(
//            IntPtr hHash,
//            [In] byte[] pbInput,
//            int cbInput,
//            uint dwFlags);

//        [DllImport("bcrypt.dll")]
//        public static extern uint BCryptFinishHash(
//            IntPtr hHash,
//            [Out] byte[] pbOutput,
//            int cbOutput,
//            uint dwFlags);

//        [DllImport("bcrypt.dll")]
//        public static extern uint BCryptCloseAlgorithmProvider(
//            IntPtr hAlgorithm,
//            uint dwFlags);

//        [DllImport("bcrypt.dll")]
//        public static extern uint BCryptDestroyHash(
//            IntPtr hHash);
//    }

//    class Program
//    {
//        static void Main()
//        {
//            IntPtr hAlgorithm = IntPtr.Zero;
//            IntPtr hHash = IntPtr.Zero;

//            uint status = NativeMethods.BCryptOpenAlgorithmProvider(out hAlgorithm, NativeMethods.BCRYPT_SHA512_ALGORITHM, null, 0);
//            if (status != NativeMethods.BCRYPT_SUCCESS)
//            {
//                throw new CryptographicException("Unable to open algorithm provider. Status code: " + status);
//            }

//            try
//            {
//                string userInput = "Admin@xyz!";
//                byte[] byteInput = Encoding.UTF8.GetBytes(userInput);

//                byte[] hash = new byte[NativeMethods.BCRYPT_HASH_LENGTH];

//                status = NativeMethods.BCryptCreateHash(hAlgorithm, out hHash, IntPtr.Zero, 0, null, 0, 0);
//                if (status != NativeMethods.BCRYPT_SUCCESS)
//                {
//                    throw new CryptographicException("Unable to create hash. Status code: " + status);
//                }

//                status = NativeMethods.BCryptHashData(hHash, byteInput, byteInput.Length, 0);
//                if (status != NativeMethods.BCRYPT_SUCCESS)
//                {
//                    throw new CryptographicException("Unable to hash data. Status code: " + status);
//                }

//                status = NativeMethods.BCryptFinishHash(hHash, hash, hash.Length, 0);
//                if (status != NativeMethods.BCRYPT_SUCCESS)
//                {
//                    throw new CryptographicException("Unable to finalize hash. Status code: " + status);
//                }

//                Console.WriteLine("Hashed Output: " + BitConverter.ToString(hash).Replace("-", "").ToLower());
//            }
//            finally
//            {
//                if (hHash != IntPtr.Zero)
//                {
//                    NativeMethods.BCryptDestroyHash(hHash);
//                }

//                if (hAlgorithm != IntPtr.Zero)
//                {
//                    NativeMethods.BCryptCloseAlgorithmProvider(hAlgorithm, 0);
//                }
//            }
//        }
//    }

//}
