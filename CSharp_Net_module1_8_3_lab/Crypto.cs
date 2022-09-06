using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.RightsManagement;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace CSharp_Net_module1_8_3_lab
{
    class Crypto
    {
        // 1) Change parameters in method and returned type
        public string Crypting(string text)
        {
            // 2) Create crypto provider object
            MD5 mdProvider = MD5CryptoServiceProvider.Create();
            // use class MD5CryptoServiceProvider
            byte[] bytes = mdProvider.ComputeHash(Encoding.ASCII.GetBytes(text));
            // 3) Create crypto hash by invoking method ComputeHash() of class MD5CryptoServiceProvider
            string newStr =  string.Join(" ", bytes.Select(x => x.ToString("x2")));

            // 4) Add encrypted data to new string in hexadesimal form


            // Note1: use array of bytes as encrypted value (convert string to byte and vise versa)

            // Note2: use numeric format "x" to represent data in hexadesimal form. 
            // Number of digits in in the result string must be 2 (use precision)

            File.WriteAllText("file.txt", newStr);
            // 5) Save encrypted data to file
            return newStr;
        }

        // 6) Change parameters in method and returned type
        public bool Check(string text)
        {
            // 7) Create crypto provider object
            // use class MD5CryptoServiceProvider
            MD5 mdProvider = MD5CryptoServiceProvider.Create();
            // 8) Create crypto hash by invoking method ComputeHash() of class MD5CryptoServiceProvider
            byte[] bytes = mdProvider.ComputeHash(Encoding.ASCII.GetBytes(text));


            // 9) Add encrypted data to new string in hexadesimal form


            // Note1: use array of bytes as encrypted value (convert string to byte and vise versa)

            // Note2: use numeric format "x" to represent data in hexadesimal form. 
            // Number of digits in in the result string must be 2 (use precision)
            string newStr = string.Join(" ", bytes.Select(x => x.ToString("x2")));
            // 10) Read data from the file
            string fileStr = File.ReadAllText("file.txt", Encoding.ASCII);
            return string.Compare(fileStr, newStr) == 0 ? true : false;
            
            // 11) compare crypted data and file data

        }

        // 12) Change parameters in method and returned type
        public byte[] Signaturing(CngAlgorithm algorithm)
        {
            CngKey key = CngKey.Create(algorithm);
            // 13) use class CngKey to create signature key (declare object and invoke method Create())
            // use as parameter of method Create() some value of class CngAlgorithm (any algorythm)
            byte[] publicKey = key.Export(CngKeyBlobFormat.GenericPublicBlob);
            // 14) Create public key as array of bytes. Use method Export() of class CngKey, which will return byte array
            // use CngKeyBlobFormat.GenericPublicBlob as parameter
            string data = File.ReadAllText("file.txt", Encoding.ASCII);
            ECDsaCng signature = new ECDsaCng(key);
            // 15) Create signatere. Save it to array of bytes.
            byte[] sign = signature.SignData(Encoding.ASCII.GetBytes(data));
            //  Declare object of class ECDsaCng. Use declared object of CngKey as parameter of constructor.
            // Save to byte array result of method SignData() of class ECDsaCng with value of public key as parameter 
            File.WriteAllText("file.txt", data);
            // Note: don't forget to clear with method Clear() of class ECDsaCng
            signature.Clear();
            return sign;
        }

        // 16) Change parameters in method and returned type
        // method must use created signature public key and signature 
        public bool VerifySignature(byte[] publicKey)
        {
            CngKey cngKey = CngKey.Import(publicKey, CngKeyBlobFormat.GenericPublicBlob);

            // 17) Use class CngKey to create new signature key to check data (declare object and invoke method Import());
            // use as parameter of method Import() values of signature public key, and the same format as in creating of signature key
            // (use CngKeyBlobFormat.GenericPublicBlob)
            ECDsaCng signature = new ECDsaCng(cngKey);
            // 18) Verify input data. Declare new object of class ECDsaCng with created signature key on prevous step
            byte[] data = Encoding.ASCII.GetBytes(File.ReadAllText("file.txt", Encoding.ASCII));
            // 19) Invoke method VerifyData() to verify input data;
            CngAlgorithm algorithm = new CngAlgorithm("3DES");
            byte[] sign = Signaturing(algorithm);
            if(signature.VerifyData(data, sign))
            {
                signature.Clear();
                return true;
            }
            else
            {
                signature.Clear();
                return false;
            }
            // 1st parameter - input data (as byte array)
            // 2nd parameter - created aerlier signature (in method Signaturing())
            // Note: don't forget to clear with method Clear() of class ECDsaCng
        }
    }
}
