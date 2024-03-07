using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += (char)((((int)(plainText[i] - 'a') + key) % 26) + 'a');
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int idx = ((((int)(cipherText[i] - 'a') - key) % 26) + 26) % 26;
                plainText += (char)(idx + 'a');
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int key = ((((int)(cipherText[0] - 'a') - (int)(plainText[0] - 'a')) % 26) + 26) % 26;
            return key;
        }
    }
}
