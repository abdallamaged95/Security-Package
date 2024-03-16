using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            var table = new Dictionary<char, char>();
            var C_T = cipherText.ToUpper().ToCharArray().Distinct().ToArray();
            var P_T = plainText.ToUpper().ToCharArray().Distinct().ToArray();

            char[] m = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            var mytable = new Dictionary<char, char>();
            char[] ar = "123456789!@#$%^&*+=-~".ToCharArray();
            int n = 0;


            for (int i = 0; i < C_T.Length; i++)
            {
                table.Add(P_T[i], C_T[i]);
            }
            /////////////////////////////////////
            for (int h = 0; h < 26; h++)
            {
                if (table.ContainsKey(m[h]))
                {
                    mytable.Add(m[h], table[m[h]]);
                }
                else
                {

                    mytable.Add(m[h], ar[n]);
                    n++;
                }


            }

            int counter = 0;
            char[] x = new char[26];
            string res;
            foreach (KeyValuePair<char, char> pair in mytable)
            {

                x[counter] = pair.Value;
                counter++;
            }
            res = new string(x);


            return res.ToLower();

        }

        public string Decrypt(string cipherText, string key)
        {
            char[] myvalue = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            char[] mykey = key.ToUpper().ToCharArray();

            char[] C_T = cipherText.ToUpper().ToCharArray();
            char[] P_T = new char[cipherText.Length];


            var mytable = new Dictionary<char, char>();

            for (int i = 0; i < mykey.Length; i++)
            {
                mytable.Add(mykey[i], myvalue[i]);
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                P_T[i] = mytable[C_T[i]];

            }

            string res = new string(P_T);
            return res;

        }

        public string Encrypt(string plainText, string key)
        {
            char[] mykey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            char[] myvalue = key.ToUpper().ToCharArray();
            char[] P_T = plainText.ToUpper().ToCharArray();
            char[] C_T = new char[plainText.Length];


            var mytable = new Dictionary<char, char>();

            for (int i = 0; i < mykey.Length; i++)
            {
                mytable.Add(mykey[i], myvalue[i]);
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                C_T[i] = mytable[P_T[i]];

            }

            string res = new string(C_T);
            return res;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            char[] table = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower().ToCharArray();
            cipher = cipher.ToLower();
            Dictionary<char, int> freq = new Dictionary<char, int>();

            for (int i = 0; i < cipher.Length; i++)
            {
                if (freq.ContainsKey(cipher[i]))
                {
                    freq[cipher[i]]++;
                }
                else
                {
                    freq.Add(cipher[i], 1);
                }

            }
            Dictionary<char, int> Orderdfreq = (Dictionary<char, int>)freq.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            Dictionary<char, char> Thetable = new Dictionary<char, char>();
            int counter = 0;
            foreach (var x in Orderdfreq)
            {
                Thetable.Add(x.Key, table[counter]);
                counter++;
            }
            string s = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                s += Thetable[cipher[i]];
            }
            return s;

        }
    }
}
