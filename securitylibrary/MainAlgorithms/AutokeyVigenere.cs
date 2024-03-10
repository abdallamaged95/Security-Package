using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int x = (int)(plainText[i] - 'a'), z = (int)(cipherText[i] - 'a');
                char y = (char)(((((z - x) % 26) + 26) % 26) + 'a');
                key += y;
            }
            key = RemoveRepeated(key, plainText);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            //if (key.Length != cipherText.Length)
            //    key = GetKeyStream(key, cipherText);
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int x = (int)(key[i] - 'a'), z = (int)(cipherText[i] - 'a');
                char y = (char)(((((z - x) % 26) + 26) % 26) + 'a');
                plainText += y;
                key += y;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            if (key.Length != plainText.Length)
                key = GetKeyStream(key, plainText);
            string cipherText = "";
            for (int i = 0; i < key.Length; i++)
            {
                int x = (int)(key[i] - 'a'), y = (int)(plainText[i] - 'a');
                char z = (char)(((x + y) % 26) + 'a');
                cipherText += z;
            }
            return cipherText;
        }

        public string GetKeyStream(string key, string plainText)
        {
            int idx = -1;
            while (key.Length < plainText.Length)
                key += plainText.ElementAt(((++idx) % plainText.Length));
            return key;
        }

        public string RemoveRepeated(string key, string plainText)
        {
            //myLabel:
            for (int i = plainText.Length - 1; i >= 0; i--)
            {
                string b = plainText.Substring(0, i+1);
                int idx = key.IndexOf(b);
                if (idx != -1)
                {
                    key = RemoveRepeated(key.Substring(0, idx), plainText);
                    break;
                }
            }
            return key;
        }
    }
}
