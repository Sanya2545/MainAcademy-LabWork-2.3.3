using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CSharp_Net_module1_8_3_lab
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = "Hello World !";
            Crypto crypto = new Crypto();
            crypto.Crypting(text);
            if(crypto.Check(text))
            {
                Console.WriteLine("Encrypted text is the same !");
            }
            else
            {
                Console.WriteLine("Encrypted text isn't the same !");
            }
            CngAlgorithm alg = CngAlgorithm.ECDiffieHellmanP521;
            crypto.Signaturing(alg);
            CngKey cngKey = CngKey.Create(alg);
            byte[] publicKey = cngKey.Export(CngKeyBlobFormat.GenericPublicBlob);
            if(crypto.VerifySignature(publicKey))
            {
                Console.WriteLine("Signature was verified !");
            }
            else
            {
                Console.WriteLine("Signature wasn't verified !");
            }
            //20) Invoke methods and print results
        }
    }
}
