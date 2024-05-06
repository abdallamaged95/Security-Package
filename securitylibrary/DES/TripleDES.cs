using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string first = des.Decrypt(cipherText, key[0]);
            string second = des.Encrypt(cipherText, key[1]);
            string third = des.Decrypt(cipherText, key[0]);

            return third;

        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            string first = des.Encrypt(plainText, key[0]);
            string second = des.Decrypt(plainText, key[1]);
            string third = des.Encrypt(plainText, key[0]);

            return third;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
