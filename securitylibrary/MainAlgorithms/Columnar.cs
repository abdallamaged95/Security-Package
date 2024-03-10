using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //plainText = "computerscience";
            //cipherText = "cusnpremeieotcc";
            
            cipherText = cipherText.ToLower();
            char c1 = cipherText[0], c2 = cipherText[1];
            List<int> key = null;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == c1)
                {
                    for (int j = i+1; j < plainText.Length; j++)
                    {
                        if (plainText[j] == c2)
                        {
                            int cols = j - i;
                            string[] cipherCols = GetColumns(plainText, cols);
                            key = GetKey(cipherCols, cipherText);
                            if (key != null)
                            {
                                string cipherTest = Encrypt(plainText, key);
                                if (cipherTest.Equals(cipherText))
                                    goto myLabel;
                            }
                        }
                    }
                }
            }
            myLabel:
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //cipherText = "ctipscoeemrnuce";
            //key = new List<int> { 1, 3, 4, 2, 5 };

            char[] cText = cipherText.ToLower().ToCharArray();
            string[] plainList = GetDecreptedCols(cipherText, key);

            int cols = key.Max();
            int rows = (int)Math.Ceiling((double)cipherText.Length / (double)cols);
            string plainText = "";
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    if (i < plainList[j].Length)
                        plainText += plainList[j][i];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //plainText = "computerscience";
            //key = new List<int> { 1, 3, 4, 2, 5 };

            int cols = key.Max();
            int rows = (int)Math.Ceiling((double)plainText.Length / (double)cols);
            string[] cipherList = GetColumns(plainText, cols);
            
            string cipherText = "";
            for (int i = 0; i < cols; i++)
            {
                int idx = key.IndexOf(i + 1);
                if (idx != -1 && idx < cipherList.Length)
                    cipherText += cipherList[idx];
            }
            
            return cipherText;
        }

        public List<int> GetKey(string[] cipherList, string cipherText)
        {
            int rows = (int)Math.Ceiling((double)cipherText.Length / (double)cipherList.Length);
            List<int> key = new List<int>(new int[cipherList.Length]);
            
            for (int i = 0; i < cipherList.Length; i++)
            {
                if (cipherText.IndexOf(cipherList[i]) == -1)
                    return null;
                if (cipherList[i].Length < rows)
                    cipherText = cipherText.Insert(cipherText.IndexOf(cipherList[i]), "x");
            }
            
            for (int i = 0; i < cipherList.Length; i++)
                key[i] = (cipherText.IndexOf(cipherList[i]) / rows)+1;
            
            return key;
        }

        public string[] GetColumns(string plainText, int cols)
        {
            string[] cipherList = new string[cols];
            int idx = 0;
            for (int i = 0; i < cols; i++)
            {
                string col = "";
                for (int j = i; j < plainText.Length; j += cols)
                    col += plainText[j];
                cipherList[idx] = col;
                idx++;
            }
            return cipherList;
        }

        public string[] GetDecreptedCols(String cipherText, List<int> key)
        {
            int cols = key.Max();
            int rows = (int)Math.Ceiling((double)cipherText.Length / (double)cols);
            int[] columns = new int[cols];
            for (int i = 0; i < cols; i++)
                columns[i] = rows;
            int x = cipherText.Length % cols, idx = cols - 1;
            while (--x > 0)
            {
                columns[idx]--;
                idx--;
            }
            string[] colsList = new string[cols];
            int start = 0;
            for (int i = 0; i < cols; i++)
            {
                int len = columns[key.IndexOf(i+1)];
                colsList[key.IndexOf(i+1)] = cipherText.Substring(start, len);
                start += len;
            }
            return colsList;
        }
    }
}
