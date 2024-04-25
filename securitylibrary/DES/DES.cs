using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        // Reading the matrices in the files.
        static int[,] PC1 = {
            {57, 49, 41, 33,  25,  17, 9 },
            {1 , 58, 50, 42,  34,  26, 18},
            {10, 2 , 59, 51,  43,  35, 27},
            {19, 11, 3 , 60,  52,  44, 36},
            {63, 55, 47, 39,  31,  23, 15},
            {7 , 62, 54, 46,  38,  30, 22},
            {14, 6 , 61, 53,  45,  37, 29},
            {21, 13, 5 , 28,  20,  12, 4}
        };
        static int[,] PC2 = {
            { 14, 17, 11, 24, 1 , 5 },
            { 3 , 28, 15, 6 , 21, 10 },
            { 23, 19, 12, 4 , 26, 8 },
            { 16, 7 , 27, 20, 13, 2 },
            { 41, 52, 31, 37, 47, 55 },
            { 30, 40, 51, 45, 33, 48 },
            { 44, 49, 39, 56, 34, 53 },
            { 46, 42, 50, 36, 29, 32 }
        };
        static int[,] IP = {
            { 58, 50, 42, 34, 26, 18, 10, 2 },
            { 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 },
            { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9 ,1 },
            { 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 },
            { 63, 55, 47, 39, 31, 23, 15, 7 }
        };
        static int[,] IPinverse = {
            { 40, 8, 48, 16, 56, 24, 64, 32 },
            { 39, 7, 47, 15, 55, 23, 63, 31 },
            { 38, 6, 46, 14, 54, 22, 62, 30 },
            { 37, 5, 45, 13, 53, 21, 61, 29 },
            { 36, 4, 44, 12, 52, 20, 60, 28 },
            { 35, 3, 43, 11, 51, 19, 59, 27 },
            { 34, 2, 42, 10, 50, 18, 58, 26 },
            { 33, 1, 41, 9 , 49, 17, 57, 25 }
        };
        static int[,] Expansion = {
            { 32, 1 , 2 , 3 , 4 , 5 },
            { 4 , 5 , 6 , 7 , 8 , 9 },
            { 8 , 9 , 10, 11, 12, 13 },
            { 12, 13, 14, 15, 16, 17 },
            { 16, 17, 18, 19, 20, 21 },
            { 20, 21, 22, 23, 24, 25 },
            { 24, 25, 26, 27, 28, 29 },
            { 28, 29, 30, 31, 32, 1 }
        };
        static int[,] P = {
            { 16, 7 , 20, 21 },
            { 29, 12, 28, 17 },
            { 1 , 15, 23, 26 },
            { 5 , 18, 31, 10 },
            { 2 , 8 , 24, 14 },
            { 32, 27, 3 , 9 },
            { 19, 13, 30, 6 },
            { 22, 11, 4 , 25 }
        };
        static int[,] S1 = {
            { 14, 4 , 13, 1, 2 , 15, 11, 8 , 3 , 10, 6 , 12, 5 , 9 , 0, 7 },
            { 0 , 15, 7 , 4, 14, 2 , 13, 1 , 10, 6 , 12, 11, 9 , 5 , 3, 8 },
            { 4 , 1 , 14, 8, 13, 6 , 2 , 11, 15, 12, 9 , 7 , 3 , 10, 5, 0 },
            { 15, 12, 8 , 2, 4 , 9 , 1 , 7 , 5 , 11, 3 , 14, 10, 0 , 6, 13 },
        };
        static int[,] S2 = {
            { 15, 1 , 8 , 14, 6 , 11, 3,  4 , 9 , 7, 2 , 13, 12, 0, 5 , 10 },
            { 3 , 13, 4 , 7 , 15, 2 , 8,  14, 12, 0, 1 , 10, 6 , 9, 11, 5 },
            { 0 , 14, 7 , 11, 10, 4 , 13, 1 , 5 , 8, 12, 6 , 9 , 3, 2 , 15 },
            { 13, 8 , 10, 1 , 3 , 15, 4,  2 , 11, 6, 7 , 12, 0 , 5, 14, 9 }
        };
        static int[,] S3 = {
            {10, 0 ,9 , 14, 6, 3 , 15, 5 , 1 , 13, 12, 7 , 11, 4 , 2 , 8},
            {13, 7 ,0 , 9 , 3, 4 , 6 , 10, 2 , 8 , 5 , 14, 12, 11, 15, 1},
            {13, 6 ,4 , 9 , 8, 15, 3 , 0 , 11, 1 , 2 , 12, 5 , 10, 14, 7},
            { 1, 10,13, 0 , 6, 9 , 8 , 7 , 4 , 15, 14, 3 , 11, 5 , 2 , 12}
        };
        static int[,] S4 = {
            {7 , 13, 14, 3, 0 , 6 , 9 , 10, 1 , 2, 8, 5 , 11, 12, 4 , 15},
            {13, 8 , 11, 5, 6 , 15, 0 , 3 , 4 , 7, 2, 12, 1 , 10, 14, 9 },
            {10, 6 , 9 , 0, 12, 11, 7 , 13, 15, 1, 3, 14, 5 , 2 , 8 , 4 },
            { 3, 15, 0 , 6, 10, 1 , 13, 8 , 9 , 4, 5, 11, 12, 7 , 2 , 14}
        };
        static int[,] S5 = {
            { 2 , 12, 4 , 1 , 7 , 10, 11, 6 , 8 , 5 , 3 , 15, 13, 0, 14, 9 },
            { 14, 11, 2 , 12, 4 , 7 , 13, 1 , 5 , 0 , 15, 10, 3 , 9, 8 , 6 },
            { 4 , 2 , 1 , 11, 10, 13, 7 , 8 , 15, 9 , 12, 5 , 6 , 3, 0 , 14 },
            { 11, 8 , 12, 7 , 1 , 14, 2 , 13, 6 , 15, 0 , 9 , 10, 4, 5 , 3 }
        };
        static int[,] S6 = {
            {12, 1 , 10, 15, 9, 2 , 6 , 8 , 0 , 13, 3 , 4 , 14, 7 , 5 , 11},
            {10, 15, 4 , 2 , 7, 12, 9 , 5 , 6 , 1 , 13, 14, 0 , 11, 3 , 8},
            {9 , 14, 15, 5 , 2, 8 , 12, 3 , 7 , 0 , 4 , 10, 1 , 13, 11, 6},
            {4 , 3 , 2 , 12, 9, 5 , 15, 10, 11, 14, 1 , 7 , 6 , 0 , 8 , 13}
        };
        static int[,] S7 = {
            { 4 , 11, 2 , 14, 15, 0, 8 , 13, 3 , 12, 9, 7 , 5 , 10, 6, 1 },
            { 13, 0 , 11, 7 , 4 , 9, 1 , 10, 14, 3 , 5, 12, 2 , 15, 8, 6 },
            { 1 , 4 , 11, 13, 12, 3, 7 , 14, 10, 15, 6, 8 , 0 , 5 , 9, 2 },
            { 6 , 11, 13, 8 , 1 , 4, 10, 7 , 9 , 5 , 0, 15, 14, 2 , 3, 12 }
        };
        static int[,] S8 = {
            { 13, 2 , 8 , 4, 6 , 15, 11, 1 , 10, 9 , 3 , 14, 5 , 0 , 12, 7 },
            { 1 , 15, 13, 8, 10, 3 , 7 , 4 , 12, 5 , 6 , 11, 0 , 14, 9 , 2 },
            { 7 , 11, 4 , 1, 9 , 12, 14, 2 , 0 , 6 , 10, 13, 15, 3 , 5 , 8 },
            { 2 , 1 , 14, 7, 4 , 10, 8 , 13, 15, 12, 9 , 0 , 3 , 5 , 6 , 11 }
        };
        static List<int[,]> SBoxArray = new List<int[,]>() { S1, S2, S3, S4, S5, S6, S7, S8 };
        static int[,] numberOfLeftShifts = {
            { 1 , 1 },
            { 2 , 1 },
            { 3 , 2 },
            { 4 , 2 },
            { 5 , 2 },
            { 6 , 2 },
            { 7 , 2 },
            { 8 , 2 },
            { 9 , 1 },
            { 10, 2 },
            { 11, 2 },
            { 12, 2 },
            { 13, 2 },
            { 14, 2 },
            { 15, 2 },
            { 16, 1 }
        };

        // Function to read a matrix from a text file.
        public static int[,] Read(string filePath, int N, int M)
        {
            int[,] file = new int[N, M]; // replace the dimensions as per your requirement

            // read the file contents using StreamReader
            using (StreamReader reader = new StreamReader(@filePath))
            {
                int i = 0, j = 0;
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();
                    string[] values = line.Split(' '); // assuming values are separated by space

                    foreach (string value in values)
                    {
                        file[i, j] = int.Parse(value);
                        j++;
                    }
                    i++;
                    j = 0;
                }
            }
            return file;
        }

        // Generic function to perform the matrix indexing.
        public static string Generic(int N, int M, string x, int[,] file)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < N; i++)
                for (int j = 0; j < M; j++)
                    sb.Append(x[file[i, j] - 1]);

            return sb.ToString();
        }

        // Shifting binary numbers to left by the "shiftAmount".
        public static string ShiftLeft(string key, int shiftAmount)
        {
            return key.Substring(shiftAmount) + key.Substring(0, shiftAmount);
        }

        public static string[] Round(string text, string key)
        {
            string L = text.Substring(0, 32);
            string R = text.Substring(32, 32);
            string e = Generic(8, 6, R, Expansion); // 48-bit

            // XORing the output from the expansion with the key from PC2.
            StringBuilder ExpansionXORKey = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                if (e[i] == key[i])
                    ExpansionXORKey.Append("0");
                else
                    ExpansionXORKey.Append("1");
            }
            string eXORk = ExpansionXORKey.ToString();

            // Dividing the output of the XOR to 8 blocks of 6-bits each to be given to the S boxes.
            string[] sBoxArray = new string[8];
            int c = 0;
            for (int i = 0; i < 48; i += 6)
            {
                sBoxArray[c] = eXORk.Substring(i, 6);
                c++;
            }

            string col, row;
            StringBuilder Sbox = new StringBuilder();
            //Doing the S Box function.
            for (int i = 0; i < 8; i++)
            {
                row = sBoxArray[i].Substring(0, 1) + sBoxArray[i].Substring(5);
                col = sBoxArray[i].Substring(1, 4);

                int rowNum = Convert.ToInt32(row, 2);
                int colNum = Convert.ToInt32(col, 2);

                int index = SBoxArray[i][rowNum, colNum];

                string binary = Convert.ToString(index, 2).PadLeft(4, '0');
                Sbox.Append(binary); // 32-bit
            }

            string p = Generic(8, 4, Sbox.ToString(), P); // 32-bit

            // XORing the output from the S boxes with the L from the previous round.
            StringBuilder SboxXORL = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                if (p[i] == L[i])
                    SboxXORL.Append("0");
                else
                    SboxXORL.Append("1");
            }

            string newR = SboxXORL.ToString();
            string newL = R;

            string[] LR = { newL, newR };

            return LR;
        }

        // Generic function for encryption and decryption (as they are the same code).
        public static string EncryptionDecryption(string text, string key, bool encrypt)
        {
            //throw new NotImplementedException();

            string Text = text.Substring(2, text.Length - 2);
            string binaryText = string.Join(String.Empty, Text.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));

            string k = key.Substring(2, key.Length - 2);
            string binaryKey = string.Join(String.Empty, k.Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));

            string afterPC1 = Generic(8, 7, binaryKey, PC1); //56-bit

            string C = afterPC1.Substring(0, 28);
            string D = afterPC1.Substring(28, 28);

            string[] cArray = new string[16];
            string[] dArray = new string[16];

            for (int i = 0; i < 16; i++)
            {
                cArray[i] = ShiftLeft(C, numberOfLeftShifts[i, 1]);
                C = cArray[i];
            }
            for (int i = 0; i < 16; i++)
            {
                dArray[i] = ShiftLeft(D, numberOfLeftShifts[i, 1]);
                D = dArray[i];
            }

            string[] pc2Array = new string[16];
            for (int i = 0; i < 16; i++)
            {
                string x = cArray[i] + dArray[i];
                pc2Array[i] = Generic(8, 6, x, PC2); // 48-bit
            }

            string ip = Generic(8, 8, binaryText, IP); // 64-bit
            if (encrypt)
            {
                for (int i = 0; i < 16; i++)
                {
                    string[] LR = Round(ip, pc2Array[i]); // 64-bit
                    ip = LR[0] + LR[1];
                }
            }
            else // decrypt
            {
                for (int i = 15; i >= 0; i--)
                {
                    string[] LR = Round(ip, pc2Array[i]); // 64-bit
                    ip = LR[0] + LR[1];
                }
            }

            string swap = ip.Substring(32, 32) + ip.Substring(0, 32);
            string generatedText = Generic(8, 8, swap, IPinverse); // 64-bit

            byte[] bytes = new byte[8];
            for (int i = 0; i < 8; i++)
                bytes[i] = Convert.ToByte(generatedText.Substring(i * 8, 8), 2);

            string hexString = BitConverter.ToString(bytes).Replace("-", "");

            hexString = "0x" + hexString;

            return hexString;
        }

        public override string Decrypt(string cipherText, string key)
        {
            return EncryptionDecryption(cipherText, key, false);
        }
        public override string Encrypt(string plainText, string key)
        {
            return EncryptionDecryption(plainText, key, true);
        }
    }
}