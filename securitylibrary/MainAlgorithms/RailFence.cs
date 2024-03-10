using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int key = 0;
            
            for (int j = 1; j < plainText.Length; j++)
            {
                if (plainText[j] == cipherText[1])
                {
                    key = j;
                    string testPlain = Decrypt(cipherText, key);
                    if (plainText.Equals(Preprocessing(testPlain)))
                        break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            char[] cText = cipherText.ToLower().ToCharArray();
            int step = (int)Math.Ceiling((double)cipherText.Length / (double)key);
            string plainText = "";
            for (int i = 0; i < cText.Length; i++)
                if (cText[i] != '-')
                    for (int j = i; j <  cText.Length; j += step)
                    {
                        plainText += cText[j];
                        cText[j] = '-';
                    }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            char[] pText = plainText.ToLower().ToCharArray();
            string cipherText = "";
            for (int i = 0; i < pText.Length; i++) 
                if (pText[i] != '-')
                {
                    for (int j = i; j < pText.Length; j += key)
                    {
                        cipherText += pText[j];
                        pText[j] = '-';
                    }
                }
            return cipherText;
        }

        public string Preprocessing(string Text)
        {
            char[] tmpText = Text.ToLower().ToCharArray();
            int idx = tmpText.Length - 1;
            while (tmpText[idx] == 'x')
            {
                tmpText[idx] = '-';
                idx--;
            }
            Text = new string(tmpText);
            Text = Text.Replace("-", string.Empty);
            return Text;
        }
    }
}
