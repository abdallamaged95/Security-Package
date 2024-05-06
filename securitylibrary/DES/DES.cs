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
    public class DES : CryptographicTechnique
    {



        string ToBinary(string x)
        {
            string[] binaries = new string[16];
            binaries[0] = "0000";
            binaries[1] = "0001";
            binaries[2] = "0010";
            binaries[3] = "0011";
            binaries[4] = "0100";
            binaries[5] = "0101";
            binaries[6] = "0110";
            binaries[7] = "0111";
            binaries[8] = "1000";
            binaries[9] = "1001";
            binaries[10] = "1010";
            binaries[11] = "1011";
            binaries[12] = "1100";
            binaries[13] = "1101";
            binaries[14] = "1110";
            binaries[15] = "1111";
            string newString = "";
            int n;
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == 'A')
                    n = 10;
                else if (x[i] == 'B')
                    n = 11;
                else if (x[i] == 'C')
                    n = 12;
                else if (x[i] == 'D')
                    n = 13;
                else if (x[i] == 'E')
                    n = 14;
                else if (x[i] == 'F')
                    n = 15;
                else
                    n = int.Parse(x[i].ToString());

                newString += binaries[n];
            }
            return newString;

        }
      
        /// /////////// <summary>
        /// ///////////
        /// </summary>
        /// <param name="N"></param>
        /// <param name="M"></param>
        /// <param name="x"></param>
        /// <param name="file"></param>
        /// <returns></returns>
    
        public static string Generic(int N, int M, string x, int[,] file)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < N; i++)
                for (int j = 0; j < M; j++)
                    sb.Append(x[file[i, j] - 1]);

            return sb.ToString();
        }
        ///
        static string LeftShift(string sequence, int shiftAmount)
        {
            int length = sequence.Length;
            string shiftedSequence = "";

            for (int i = 0; i < length; i++)
            {
                int newIndex = (i + shiftAmount) % length;

                shiftedSequence += sequence[newIndex];
            }

            return shiftedSequence;
        }
        ///
        string round(string p, string k)
        {
            // separte data to L0 And R0
            int l = p.Length / 2;
            string L0 = p.Substring(0, l);
            string R0 = p.Substring(l);
            //expand
            string E_R0 = "";
            int[] E_Table =
                    {
            32, 1,  2,  3,  4,  5,
            4,  5,  6,  7,  8,  9,
            8,  9,  10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };
            for (int i = 0; i < 48; i++)
            {
                E_R0 += R0[E_Table[i] - 1];
            }
            // xor plain and key
            string ResultOfXOR ="";
            for (int i = 0; i < 48; i++)
            {
                if (E_R0[i].Equals( k[i]))
                    ResultOfXOR += "0";
                else
                    ResultOfXOR += "1";
            }
            // making S Box
            var x1 = ResultOfXOR.Substring(0, 6);
            var x2 = ResultOfXOR.Substring(6, 6);
            var x3 = ResultOfXOR.Substring(12, 6);
            var x4 = ResultOfXOR.Substring(18, 6);
            var x5 = ResultOfXOR.Substring(24, 6);
            var x6 = ResultOfXOR.Substring(30, 6);
            var x7 = ResultOfXOR.Substring(36, 6);
            var x8 = ResultOfXOR.Substring(42, 6);
            string[] EightParts = { x1, x2,x3,x4,x5,x6,x7,x8 };
           
            int row;
            int col;
            String Boxed = "";
            for (int i = 0; i < 8; i++)
            {
                row = Convert.ToInt32(EightParts[i][0].ToString() + EightParts[i][5], 2);
                col = Convert.ToInt32(EightParts[i][1].ToString() + EightParts[i][2] + EightParts[i][3] + EightParts[i][4], 2);
                Boxed += AllSboxes.S_Boxes[i][row][col];
              
            }
            // last permu
            string AfterP = "";
            int[] P =
        {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};
            for (int i = 0; i < 32; i++)
            {
                AfterP += Boxed[P[i] - 1];
            }
            // last XOR
            string R1 = "";
            for (int i = 0; i < 32; i++)
            {
                if (L0[i] == AfterP[i])
                    R1 += "0";
                else
                    R1 += "1";
            }
            string L1 = R0;
            string result = L1 + R1;
            return result;
        }


        public override string Decrypt(string cipherText, string key)
        {
            //  throw new NotImplementedException();
            cipherText = cipherText.Substring(2);
            key = key.Substring(2);

            var res = ToBinary(cipherText);
            var resKey = ToBinary(key);
            int[] initialPermutationTable =
          {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
          };

            string IpermutedData = "";
            for (int i = 0; i < 64; i++)
            {
                IpermutedData += res[initialPermutationTable[i] - 1];
            }


            string PC1_Data = "";
            int[] PC1_Table =
                         {
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
};

            for (int i = 0; i < 56; i++)
            {
                PC1_Data += resKey[PC1_Table[i] - 1];
            }

            int length = PC1_Data.Length / 2;
            string C = PC1_Data.Substring(0, length);
            string D = PC1_Data.Substring(length);
            ////////////////////
              string[] PC2_Data=new string[16];
            for (int k=0; k<16; k++)
            {
                int[] R = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

                C = LeftShift(C, R[k]);
                D = LeftShift(D, R[k]);
                /////////////////
              
                int[] PC2_Table =
                {
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
                  };
                for (int i = 0; i < 48; i++)
                {
                    PC2_Data[k] += (C + D)[PC2_Table[i] - 1];
                }
            }
           


            ///////////////

            for (int k = 15; k >= 0; k--)
            {

                IpermutedData = round(IpermutedData, PC2_Data[k]);
            }
            int l = IpermutedData.Length / 2;
            string L16 = IpermutedData.Substring(0, l);
            string R16 = IpermutedData.Substring(l);
            string bResult = R16 + L16;

            int[] inverseInitialPermutation =
{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};
            string Final = "";
            for (int i = 0; i < 64; i++)
            {
                Final += bResult[inverseInitialPermutation[i] - 1];
            }

    
            byte[] bytes = new byte[8];
            for (int i = 0; i < 8; i++)
                bytes[i] = Convert.ToByte(Final.Substring(i * 8, 8), 2);

            string hexString = BitConverter.ToString(bytes).Replace("-", "");


            hexString = "0x" + hexString;
            return hexString;

        }

        public override string Encrypt(string plainText, string key)
        {

            plainText = plainText.Substring(2);
            key = key.Substring(2);

            var res= ToBinary(plainText);
            var resKey = ToBinary(key);
            int[] initialPermutationTable =
          {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
          };

            string IpermutedData = "";
            for (int i = 0; i < 64; i++)
            {
                IpermutedData += res[initialPermutationTable[i] - 1];
            }


            string PC1_Data = "";
            int[] PC1_Table =
                         {
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
};
   
            for (int i = 0; i < 56; i++)
            {
                PC1_Data += resKey[PC1_Table[i] - 1];
            }

            int length = PC1_Data.Length / 2;
            string C = PC1_Data.Substring(0, length);
            string D = PC1_Data.Substring(length);

            
            ///////////////

            for (int k = 0; k < 16; k++)
            {
                int[] R = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

                 C = LeftShift(C, R[k]);
                 D  = LeftShift(D, R[k]);
                /////////////////
                string PC2_Data = "";
                int[] PC2_Table =
                {
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
                  };
                for (int i = 0; i < 48; i++)
                {
                    PC2_Data += (C + D)[PC2_Table[i] - 1];
                }

                IpermutedData= round(IpermutedData, PC2_Data);
            }
            int l = IpermutedData.Length / 2;
            string L16 = IpermutedData.Substring(0, l);
            string R16 = IpermutedData.Substring(l);
            string bResult=R16+ L16;

            int[] inverseInitialPermutation =
{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};
            string Final = "";
            for (int i = 0; i < 64; i++)
            {
                Final += bResult[inverseInitialPermutation[i] - 1];
            }

            byte[] bytes = new byte[8];
            for (int i = 0; i < 8; i++)
                bytes[i] = Convert.ToByte(Final.Substring(i * 8, 8), 2);

            string hexString = BitConverter.ToString(bytes).Replace("-", "");


            hexString = "0x" + hexString;
            return hexString;




        }
    

    }
    internal class AllSboxes
    {
        public static string[][][] S_Boxes =
{
    // S-box 1
    new string[4][]
    {
        new string[] {"1110", "0100", "1101", "0001", "0010", "1111", "1011", "1000", "0011", "1010", "0110", "1100", "0101", "1001", "0000", "0111"},
        new string[] {"0000", "1111", "0111", "0100", "1110", "0010", "1101", "0001", "1010", "0110", "1100", "1011", "1001", "0101", "0011", "1000"},
        new string[] {"0100", "0001", "1110", "1000", "1101", "0110", "0010", "1011", "1111", "1100", "1001", "0111", "0011", "1010", "0101", "0000"},
        new string[] {"1111", "1100", "1000", "0010", "0100", "1001", "0001", "0111", "0101", "1011", "0011", "1110", "1010", "0000", "0110", "1101"}
    },

    // S-box 2
    new string[4][]
    {
        new string[] {"1111", "0001", "1000", "1110", "0110", "1011", "0011", "0100", "1001", "0111", "0010", "1101", "1100", "0000", "0101", "1010"},
        new string[] {"0011", "1101", "0100", "0111", "1111", "0010", "1000", "1110", "1100", "0000", "0001", "1010", "0110", "1001", "1011", "0101"},
        new string[] {"0000", "1110", "0111", "1011", "1010", "0100", "1101", "0001", "0101", "1000", "1100", "0110", "1001", "0011", "0010", "1111"},
        new string[] {"1101", "1000", "1010", "0001", "0011", "1111", "0100", "0010", "1011", "0110", "0111", "1100", "0000", "0101", "1110", "1001"}
    },

    // S-box 3
    new string[4][]
    {
        new string[] {"1010", "0000", "1001", "1110", "0110", "0011", "1111", "0101", "0001", "1101", "1100", "0111", "1011", "0100", "0010", "1000"},
        new string[] {"1101", "0111", "0000", "1001", "0011", "0100", "0110", "1010", "0010", "1000", "0101", "1110", "1100", "1011", "1111", "0001"},
        new string[] {"1101", "0110", "0100", "1001", "1000", "1111", "0011", "0000", "1011", "0001", "0010", "1100", "0101", "1010", "1110", "0111"},
        new string[] {"0001", "1010", "1101", "0000", "0110", "1001", "1000", "0111", "0100", "1111", "1110", "0011", "1011", "0101", "0010", "1100"}
    },

    // S-box 4
    new string[4][]
    {
        new string[] {"0111", "1101", "1110", "0011", "0000", "0110", "1001", "1010", "0001", "0010", "1000", "0101", "1011", "1100", "0100", "1111"},
        new string[] {"1101", "1000", "1011", "0101", "0110", "1111", "0000", "0011", "0100", "0111", "0010", "1100", "0001", "1010", "1110", "1001"},
        new string[] {"1010", "0110", "1001", "0000", "1100", "1011", "0111", "1101", "1111", "0001", "0011", "1110", "0101", "0010", "1000", "0100"},
        new string[] {"0011", "1111", "0000", "0110", "1010", "0001", "1101", "1000", "1001", "0100", "0101", "1011", "1100", "0111", "0010", "1110"}
    },

    // S-box 5
    new string[4][]
    {
        new string[] {"0010", "1100", "0100", "0001", "0111", "1010", "1011", "0110", "1000", "0101", "0011", "1111", "1101", "0000", "1110", "1001"},
        new string[] {"1110", "1011", "0010", "1100", "0100", "0111", "1101", "0001", "0101", "0000", "1111", "1010", "0011", "1001", "1000", "0110"},
        new string[] {"0100", "0010", "0001", "1011", "1010", "1101", "0111", "1000", "1111", "1001", "1100", "0101", "0110", "0011", "0000", "1110"},
        new string[] {"1011", "1000", "1100", "0111", "0001", "1110", "0010", "1101", "0110", "1111", "0000", "1001", "1010", "0100", "0101", "0011"}
    },

    // S-box 6
    new string[4][]
    {
        new string[] {"1100", "0001", "1010", "1111", "1001", "0010", "0110", "1000", "0000", "1101", "0011", "0100", "1110", "0111", "0101", "1011"},
        new string[] {"1010", "1111", "0100", "0010", "0111", "1100", "1001", "0101", "0110", "0001", "1101", "1110", "0000", "1011", "0011", "1000"},
        new string[] {"1001", "1110", "1111", "0101", "0010", "1000", "1100", "0011", "0111", "0000", "0100", "1010", "0001", "1101", "1011", "0110"},
        new string[] {"0100", "0011", "0010", "1100", "1001", "0101", "1111", "1010", "1011", "1110", "0001", "0111", "0110", "0000", "1000", "1101"}
    },

    // S-box 7
    new string[4][]
    {
        new string[] {"0100", "1011", "0010", "1110", "1111", "0000", "1000", "1101", "0011", "1100", "1001", "0111", "0101", "1010", "0110", "0001"},
        new string[] {"1101", "0000", "1011", "0111", "0100", "1001", "0001", "1010", "1110", "0011", "0101", "1100", "0010", "1111", "1000", "0110"},
        new string[] {"0001", "0100", "1011", "1101", "1100", "0011", "0111", "1110", "1010", "1111", "0110", "1000", "0000", "0101", "1001", "0010"},
        new string[] {"0110", "1011", "1101", "1000", "0001", "0100", "1010", "0111", "1001", "0101", "0000", "1111", "1110", "0010", "0011", "1100"}
    },

    // S-box 8
    new string[4][]
    {
        new string[] {"1101", "0010", "1000", "0100", "0110", "1111", "1011", "0001", "1010", "1001", "0011", "1110", "0101", "0000", "1100", "0111"},
        new string[] {"0001", "1111", "1101", "1000", "1010", "0011", "0111", "0100", "1100", "0101", "0110", "1011", "0000", "1110", "1001", "0010"},
        new string[] {"0111", "1011", "0100", "0001", "1001", "1100", "1110", "0010", "0000", "0110", "1010", "1101", "1111", "0011", "0101", "1000"},
        new string[] {"0010", "0001", "1110", "0111", "0100", "1010", "1000", "1101", "1111", "1100", "1001", "0000", "0011", "0101", "0110", "1011"}
    } };
    }


}

