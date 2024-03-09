using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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
            key = RemoveRepeated(key);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            if (key.Length != cipherText.Length)
                key = GetKeyStream(key, cipherText);
            string plainText = "";
            for (int i = 0 ; i < key.Length; i++)
            {
                int x = (int)(key[i] - 'a'), z = (int)(cipherText[i] - 'a');
                char y = (char)(((((z - x) % 26) + 26) % 26) + 'a');
                plainText += y;
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
                key += key.ElementAt(((++idx) % key.Length));
            return key;
        }

        public string RemoveRepeated(string key)
        {
            for (int i = 0; i < key.Length-1; i++)
            {
                string a = key.Substring(0, i+1);
                string b = key.Substring(i + 1, key.Length - (i + 1));
                if (a.IndexOf(b) == 0)
                {
                    key = RemoveRepeated(a);
                    break;
                }
            }
            return key;
        }
    }
}