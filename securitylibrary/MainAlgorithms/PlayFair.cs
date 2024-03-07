using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        
        public Tuple<int, int>[] map;
        public char[][] matrix;
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            InitializeMatrix(key);
            string plainText = "";
            for (int i = 0; i < cipherText.Length-1; i+=2)
            {
                plainText += GetEncryptedChars(cipherText[i], cipherText[i + 1], false);
            }
            plainText = OutputPreprocessing(plainText);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //key = "playfairexample";
            //plainText = "communication";
            plainText = InputPreprocessing(plainText.ToLower());

            InitializeMatrix(key);

            string cipherText = "";
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                cipherText += GetEncryptedChars(plainText[i], plainText[i + 1], true);
            }
            return cipherText;
        }
        public string OutputPreprocessing(string plainText)
        {
            char[] tmpText = plainText.ToCharArray();
            if (tmpText[tmpText.Length - 1] == 'x')
                tmpText[tmpText.Length - 1] = '-';

            for (int i = 1; i < tmpText.Length-1; i+=2)
                if (tmpText[i] == 'x' && tmpText[i + 1] == tmpText[i - 1])
                    tmpText[i] = '-';
            
            plainText = new string(tmpText);
            plainText = plainText.Replace("-", string.Empty);
            return plainText;
        }
        public string InputPreprocessing(string plainText)
        {
            for (int i = 0; i <  plainText.Length-1; i+=2)
            {
                if (plainText[i] == plainText[i + 1])
                    plainText = plainText.Insert(i + 1, "x");
            }
            if (plainText.Length % 2 != 0)
                plainText += "x";
            return plainText;
        }
        public string GetEncryptedChars(char c1, char c2, bool encrypt)
        {
            Tuple<int, int> loc1 = map[(int)(c1 - 'a')];
            Tuple<int, int> loc2 = map[(int)(c2 - 'a')];
            char a, b;
            if (loc1.Item1 == loc2.Item1)
            {
                a = matrix[loc1.Item1][(((loc1.Item2 + ((encrypt) ? 1 : -1)) % 5) + 5) % 5];
                b = matrix[loc2.Item1][(((loc2.Item2 + ((encrypt) ? 1 : -1)) % 5) + 5) % 5];
            }
            else if (loc1.Item2 == loc2.Item2)
            {
                a = matrix[(((loc1.Item1 + ((encrypt) ? 1 : -1)) % 5) + 5) % 5][loc1.Item2];
                b = matrix[(((loc2.Item1 + ((encrypt) ? 1 : -1)) % 5) + 5) % 5][loc2.Item2];
            }
            else
            {
                a = matrix[loc1.Item1][loc2.Item2];
                b = matrix[loc2.Item1][loc1.Item2];
            }
            return a.ToString() + b.ToString();
        }
        public void InitializeMatrix(string key)
        {
            map = new Tuple<int, int>[26];
            matrix = new char[5][];
            for (int i = 0; i < 5; i++)
                matrix[i] = new char[5];

            int idx1 = 0, idx2 = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    while (idx1 < key.Length && map[(int)(key[idx1] - 'a')] != null)
                        idx1++;
                    if (idx1 < key.Length)
                    {
                        map[(int)(key[idx1] - 'a')] = new Tuple<int, int>(i, j);
                        matrix[i][j] = key[idx1];
                        if (key[idx1] == 'i' || key[idx1] == 'j')
                        {
                            map[8] = new Tuple<int, int>(i, j);
                            map[9] = new Tuple<int, int>(i, j);
                            matrix[i][j] = 'i';
                        }
                    }
                    else
                    {
                        while (idx2 < 26 && map[idx2] != null)
                            idx2++;
                        if (idx2 < 26)
                        {
                            map[idx2] = new Tuple<int, int>(i, j);
                            matrix[i][j] = (char)(idx2 + 'a');
                            if ((char)(idx2 + 'a') == 'i' || (char)(idx2 + 'a') == 'j')
                            {
                                map[8] = new Tuple<int, int>(i, j);
                                map[9] = new Tuple<int, int>(i, j);
                                matrix[i][j] = 'i';
                            }
                        }
                    }
                }
            }
        }
    }
}
