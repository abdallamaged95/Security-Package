using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static string[,] SBox = {
            { "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
            { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
            { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
            { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
            { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
            { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
            { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
            { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
            { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
            { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
            { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
            { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
            { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
            { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
            { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
            { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
        };
        public static string[,] InvSBox = {
            { "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
            { "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" },
            { "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" },
            { "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" },
            { "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" },
            { "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
            { "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
            { "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
            { "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
            { "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
            { "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
            { "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
            { "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
            { "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
            { "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" },
            { "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" }
        };
        public static string[,] MixColumns = {
            { "02", "03", "01", "01" },
            { "01", "02", "03", "01" },
            { "01", "01", "02", "03" },
            { "03", "01", "01", "02" }
        };
        public static string[,] InvMixColumns = {
            { "0E", "0B", "0D", "09" },
            { "09", "0E", "0B", "0D" },
            { "0D", "09", "0E", "0B" },
            { "0B", "0D", "09", "0E" }
        };
        public static string[,] Rcon = {
            { "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" },
            { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00" },
            { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00" },
            { "00", "00", "00", "00", "00", "00", "00", "00", "00", "00" }
        };
        public static string[,] LTable = {
            { "00", "00", "19", "01", "32", "02", "1A", "C6", "4B", "C7", "1B", "68", "33", "EE", "DF", "03" },
            { "64", "04", "E0", "0E", "34", "8D", "81", "EF", "4C", "71", "08", "C8", "F8", "69", "1C", "C1" },
            { "7D", "C2", "1D", "B5", "F9", "B9", "27", "6A", "4D", "E4", "A6", "72", "9A", "C9", "09", "78" },
            { "65", "2F", "8A", "05", "21", "0F", "E1", "24", "12", "F0", "82", "45", "35", "93", "DA", "8E" },
            { "96", "8F", "DB", "BD", "36", "D0", "CE", "94", "13", "5C", "D2", "F1", "40", "46", "83", "38" },
            { "66", "DD", "FD", "30", "BF", "06", "8B", "62", "B3", "25", "E2", "98", "22", "88", "91", "10" },
            { "7E", "6E", "48", "C3", "A3", "B6", "1E", "42", "3A", "6B", "28", "54", "FA", "85", "3D", "BA" },
            { "2B", "79", "0A", "15", "9B", "9F", "5E", "CA", "4E", "D4", "AC", "E5", "F3", "73", "A7", "57" },
            { "AF", "58", "A8", "50", "F4", "EA", "D6", "74", "4F", "AE", "E9", "D5", "E7", "E6", "AD", "E8" },
            { "2C", "D7", "75", "7A", "EB", "16", "0B", "F5", "59", "CB", "5F", "B0", "9C", "A9", "51", "A0" },
            { "7F", "0C", "F6", "6F", "17", "C4", "49", "EC", "D8", "43", "1F", "2D", "A4", "76", "7B", "B7" },
            { "CC", "BB", "3E", "5A", "FB", "60", "B1", "86", "3B", "52", "A1", "6C", "AA", "55", "29", "9D" },
            { "97", "B2", "87", "90", "61", "BE", "DC", "FC", "BC", "95", "CF", "CD", "37", "3F", "5B", "D1" },
            { "53", "39", "84", "3C", "41", "A2", "6D", "47", "14", "2A", "9E", "5D", "56", "F2", "D3", "AB" },
            { "44", "11", "92", "D9", "23", "20", "2E", "89", "B4", "7C", "B8", "26", "77", "99", "E3", "A5" },
            { "67", "4A", "ED", "DE", "C5", "31", "FE", "18", "0D", "63", "8C", "80", "C0", "F7", "70", "07" },
        };
        public static string[,] ETable = {
            { "01", "03", "05", "0F", "11", "33", "55", "FF", "1A", "2E", "72", "96", "A1", "F8", "13", "35" },
            { "5F", "E1", "38", "48", "D8", "73", "95", "A4", "F7", "02", "06", "0A", "1E", "22", "66", "AA" },
            { "E5", "34", "5C", "E4", "37", "59", "EB", "26", "6A", "BE", "D9", "70", "90", "AB", "E6", "31" },
            { "53", "F5", "04", "0C", "14", "3C", "44", "CC", "4F", "D1", "68", "B8", "D3", "6E", "B2", "CD" },
            { "4C", "D4", "67", "A9", "E0", "3B", "4D", "D7", "62", "A6", "F1", "08", "18", "28", "78", "88" },
            { "83", "9E", "B9", "D0", "6B", "BD", "DC", "7F", "81", "98", "B3", "CE", "49", "DB", "76", "9A" },
            { "B5", "C4", "57", "F9", "10", "30", "50", "F0", "0B", "1D", "27", "69", "BB", "D6", "61", "A3" },
            { "FE", "19", "2B", "7D", "87", "92", "AD", "EC", "2F", "71", "93", "AE", "E9", "20", "60", "A0" },
            { "FB", "16", "3A", "4E", "D2", "6D", "B7", "C2", "5D", "E7", "32", "56", "FA", "15", "3F", "41" },
            { "C3", "5E", "E2", "3D", "47", "C9", "40", "C0", "5B", "ED", "2C", "74", "9C", "BF", "DA", "75" },
            { "9F", "BA", "D5", "64", "AC", "EF", "2A", "7E", "82", "9D", "BC", "DF", "7A", "8E", "89", "80" },
            { "9B", "B6", "C1", "58", "E8", "23", "65", "AF", "EA", "25", "6F", "B1", "C8", "43", "C5", "54" },
            { "FC", "1F", "21", "63", "A5", "F4", "07", "09", "1B", "2D", "77", "99", "B0", "CB", "46", "CA" },
            { "45", "CF", "4A", "DE", "79", "8B", "86", "91", "A8", "E3", "3E", "42", "C6", "51", "F3", "0E" },
            { "12", "36", "5A", "EE", "29", "7B", "8D", "8C", "8F", "8A", "85", "94", "A7", "F2", "0D", "17" },
            { "39", "4B", "DD", "7C", "84", "97", "A2", "FD", "1C", "24", "6C", "B4", "C7", "52", "F6", "01" }
        };
        public static string[,] plainMat, cipherMat, keyMat;

        static void ShiftRow(string[,] matrix, int rowIndex, int numShifts)
        {
            int len = (int)Math.Sqrt(matrix.Length);
            string[] row = new string[len];

            for (int i = 0; i < len; i++)
                row[i] = matrix[rowIndex, i];

            for (int i = 0; i < len; i++)
            {
                int newIndex = (i + numShifts) % len;
                if (newIndex < 0)
                    newIndex += len;

                matrix[rowIndex, i] = row[newIndex];
            }
        }

        public static string calcXOR(string[,] bPlain, int i, int j)
        {
            string xor = "";
            if (bPlain[i, j][0] == '0')
                xor = bPlain[i, j].Substring(1) + bPlain[i, j].Substring(0, 1);
            else
            {
                string shiftLeft = bPlain[i, j].Substring(1) + "0";

                string b1 = Convert.ToString(27, 2).PadLeft(8, '0');
                StringBuilder b1XORshifted = new StringBuilder();

                int m = 0;
                while (m < 8)
                {
                    if (shiftLeft[m] == b1[m])
                        b1XORshifted.Append("0");
                    else
                        b1XORshifted.Append("1");
                    m++;
                }
                xor = b1XORshifted.ToString();
            }
            return xor;
        }

        public static string[,] MixColumn(string[,] plain)
        {
            string[,] bMColumns = new string[4, 4];
            string[,] bPlain = new string[4, 4];

            int l = 0;
            while (l < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    bMColumns[j, l] = Convert.ToString(Convert.ToInt32(MixColumns[j, l], 16), 2).PadLeft(8, '0');
                    bPlain[j, l] = Convert.ToString(Convert.ToInt32(plain[j, l], 16), 2).PadLeft(8, '0');
                    j++;
                }
                l++;
            }

            string[,] rs = new string[4, 4];
            string[] xorResult = new string[4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (Convert.ToInt32(bMColumns[i, k], 2) == 2)
                            xorResult[k] = calcXOR(bPlain, k, j);

                        else if (Convert.ToInt32(bMColumns[i, k], 2) == 3)
                        {
                            string xor = calcXOR(bPlain, k, j);

                            string sb = "";
                            for (int m = 0; m < 8; m++)
                            {
                                if (bPlain[k, j][m] == xor[m])
                                    sb += "0";
                                else
                                    sb += "1";
                            }

                            xorResult[k] = sb;
                        }
                        else if (Convert.ToInt32(bMColumns[i, k], 2) == 1)
                            xorResult[k] = bPlain[k, j];
                    }

                    string final = "";
                    int even = 0;

                    for (int m = 0; m < 8; m++)
                    {
                        even = 0;
                        for (int q = 0; q < 4; q++)
                            if (xorResult[q][m] == '1') even++;

                        if (even % 2 == 0)
                            final += "0";
                        else
                            final += "1";
                    }

                    string hex = Convert.ToInt32(final.ToString(), 2).ToString("X2");
                    rs[i, j] = hex;
                }
            }
            return rs;
        }

        // Doing SubBytes to the whole matrix.
        public static string[,] SubstituteBytes(string[,] txt)
        {
            string[,] substituteMatrix = new string[4, 4];

            int l = 0;
            while (l < 4)
            {
                int k = 0;
                while (k < 4)
                {
                    int row = Convert.ToInt32(txt[k, l][0].ToString(), 16);
                    int column = Convert.ToInt32(txt[k, l][1].ToString(), 16);

                    substituteMatrix[k, l] = SBox[row, column];

                    k++;
                }
                l++;
            }

            return substituteMatrix;
        }

        public static string[,] Round(string[,] txt, string[,] plainkey, bool lRound)
        {
            string[,] substitudeMatrix = SubstituteBytes(txt);

            for (int i = 1; i <= 3; i++)
                ShiftRow(substitudeMatrix, i, i);

            if (!lRound)
            {
                substitudeMatrix = MixColumn(substitudeMatrix);
            }

            return AddRKeyStep(substitudeMatrix, plainkey);
        }

        public static string multInvMixColumns(string A, string B)
        {

            if (A.Length < 2) A = "0" + A;
            if (B.Length < 2) B = "0" + B;
            if (A == "00" || B == "00") return "00";
            int row1 = Convert.ToInt32(A.Substring(0, 1), 16);
            int col1 = Convert.ToInt32(A.Substring(1, 1), 16);

            int row2 = Convert.ToInt32(B.Substring(0, 1), 16);
            int col2 = Convert.ToInt32(B.Substring(1, 1), 16);

            int sum = Convert.ToInt32(LTable[row1, col1], 16) + Convert.ToInt32(LTable[row2, col2], 16);
            if (sum > Convert.ToInt32("FF", 16))
            {
                sum = sum - Convert.ToInt32("FF", 16);
            }
            string ans = sum.ToString("X2");
            int row = Convert.ToInt32(ans.Substring(0, 1), 16);
            int col = Convert.ToInt32(ans.Substring(1, 1), 16);
            return ETable[row, col];
        }
        public static string[,] invmixColumns(string[,] state)
        {
            for (int col = 0; col < 4; col++)
            {
                string[,] tempState = new string[4, 1];
                for (int i = 0; i < 4; i++)
                {
                    tempState[i, 0] = state[i, col];
                }

                string[,] tempColMixMatrix = new string[4, 1];

                for (int i = 0; i < 4; i++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        tempColMixMatrix[z, 0] = InvMixColumns[i, z];
                    }
                    string temp = "0";
                    for (int j = 0; j < 4; j++)
                    {
                        string ans = multInvMixColumns(tempColMixMatrix[j, 0], tempState[j, 0]);
                        ans = Convert.ToString(Convert.ToInt32(ans, 16), 2).PadLeft(8, '0');
                        temp = Convert.ToString((int)(Convert.ToInt32(temp, 2) ^ Convert.ToInt32(ans, 2)), 2).PadLeft(8, '0');
                    }
                    state[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                }
            }
            return state;
        }

        public static string[,] ScheduleK(string[,] k, int idx)
        {
            string[,] mtx = new string[4, 4];

            mtx[0, 0] = k[1, 3];
            mtx[1, 0] = k[2, 3];
            mtx[2, 0] = k[3, 3];
            mtx[3, 0] = k[0, 3];

            for (int i = 0; i < 4; i++)
            {
                int row = Convert.ToInt32(mtx[i, 0][0].ToString(), 16);
                int column = Convert.ToInt32(mtx[i, 0][1].ToString(), 16);

                mtx[i, 0] = SBox[row, column];
            }

            for (int i = 0; i < 4; i++)
            {
                int xorRslt = Convert.ToInt32(mtx[i, 0], 16) ^ Convert.ToInt32(k[i, 0], 16) ^ Convert.ToInt32(Rcon[i, idx], 16);
                mtx[i, 0] = xorRslt.ToString("X2");
            }

            for (int l = 1; l < 4; l++)
            {
                for (int i = 0; i < 4; i++)
                {
                    int xorResult = Convert.ToInt32(mtx[i, l - 1], 16) ^ Convert.ToInt32(k[i, l], 16);
                    mtx[i, l] = xorResult.ToString("X2");
                }
            }

            return mtx;
        }

        public static string[,] AddRKeyStep(string[,] txt, string[,] k)
        {
            string[,] mtrx = new string[4, 4];

            int l = 0;
            while (l < 4)
            {
                int i = 0;
                while (i < 4)
                {
                    int xorResult = Convert.ToInt32(txt[i, l], 16) ^ Convert.ToInt32(k[i, l], 16);
                    mtrx[i, l] = xorResult.ToString("X2");
                    i++;
                }
                l++;
            }

            return mtrx;
        }

        static string[,] inverseBoxSubtitude(string[,] fMtrx)
        {
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string cell = fMtrx[i, j];
                    if (cell.Length == 1)
                    {
                        cell = "0" + cell;
                    }
                    int row = Convert.ToInt32(cell.Substring(0, 1), 16);
                    int col = Convert.ToInt32(cell.Substring(1, 1), 16);
                    fMtrx[i, j] = InvSBox[row, col];
                    j++;
                }
                i++;
            }
            return fMtrx;
        }

        public static string[,] InvSubBytes(string[,] text)
        {
            string[,] subMatrix = new string[4, 4];

            int rowOffset = (int)'0';
            int colOffset = (int)'0';

            for (int k = 0; k < 4; k++)
            {
                for (int i = 0; i < 4; i++)
                {
                    char rowChar = text[i, k][0];
                    char colChar = text[i, k][1];

                    int row = (rowChar >= 'A') ? (rowChar - 'A' + 10) : (rowChar - rowOffset);
                    int col = (colChar >= 'A') ? (colChar - 'A' + 10) : (colChar - colOffset);

                    subMatrix[i, k] = InvSBox[row, col];
                }
            }

            return subMatrix;
        }


        static void inverseShiftRow(string[,] mtrx, int rowidx, int numShifts)
        {
            int numOfColumns = mtrx.GetLength(1);
            string[] row = new string[numOfColumns];
            int j = 0;

            while (j < numOfColumns)
            {
                row[j] = mtrx[rowidx, j];
                j++;
            }

            j = 0;
            while (j < numOfColumns)
            {
                int newIndex = (j - numShifts) % numOfColumns;
                if (newIndex < 0)
                    newIndex += numOfColumns;

                mtrx[rowidx, j] = row[newIndex];
                j++;
            }
        }

        public static string[,] roundDecimal(string[,] text, string[,] key, bool lastRound)
        {
            string[,] substitudeMatrix = AddRKeyStep(text, key);

            if (!lastRound)
            {
                substitudeMatrix = invmixColumns(substitudeMatrix);
            }

            for (int i = 1; i <= 3; i++)
               inverseShiftRow(substitudeMatrix, i, i);

            return inverseBoxSubtitude(substitudeMatrix);

        }

        public override string Decrypt(string cipherText, string key)
        {
            bool upperCase = key != key.ToLower();
            key = key.ToUpper();
            cipherText = cipherText.ToUpper();

            key = key.Substring(2);
            cipherText = cipherText.Substring(2);

            string[] keySplit = new string[16];
            for (int i = 0; i < 16; i++)
                keySplit[i] = key.Substring(i * 2, 2);

            string[,] keyMatrix = new string[4, 4];
            for (int i = 0, c = 0; i < 4; i++)
                for (int j = 0; j < 4; j++, c++)
                    keyMatrix[j, i] = keySplit[c];

            string[][,] keySchedule = new string[11][,];
            keySchedule[0] = keyMatrix;
            for (int i = 1; i < 11; i++)
                keySchedule[i] = ScheduleK(keySchedule[i - 1], i - 1);

            string[] cipherMatrix = new string[16];
            for (int i = 0; i < 16; i++)
                cipherMatrix[i] = cipherText.Substring(i * 2, 2);

            string[,] cipher = new string[4, 4];
            for (int i = 0, c = 0; i < 4; i++)
                for (int j = 0; j < 4; j++, c++)
                    cipher[j, i] = cipherMatrix[c];

            string[,] roundText = roundDecimal(cipher, keySchedule[10], true);
            for (int i = 9; i >= 1; i--)
                roundText = roundDecimal(roundText, keySchedule[i], false);

            string[,] final = AddRKeyStep(roundText, keySchedule[0]);

            if (!upperCase)
            {
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        final[i, j] = final[i, j].ToLower();
            }

            string plainText = "";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    plainText += final[j, i];

            return "0x" + plainText;
        }


        public override string Encrypt(string plainText, string key)
        {
            bool upperCase = true;
            if (key == key.ToLower())
            {
                upperCase = false;
                key = key.ToUpper();
                plainText = plainText.ToUpper();
            }

            key = key.Substring(2, key.Length - 2);
            plainText = plainText.Substring(2, plainText.Length - 2);

            string[] keySplit = new string[16];
            for (int i = 0; i < 16; i++)
                keySplit[i] = key.Substring(i * 2, 2);

            string[,] keyMatrix = new string[4, 4];
            int c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = keySplit[c];
                    c++;
                }
            }

            string[][,] arr3D = new string[11][,];
            arr3D[0] = keyMatrix;
            for (int i = 1; i < 11; i++)
                arr3D[i] = ScheduleK(arr3D[i - 1], i - 1);

            string[] plainMatrix = new string[16];
            for (int i = 0; i < 16; i++)
                plainMatrix[i] = plainText.Substring(i * 2, 2);

            string[,] plain = new string[4, 4];
            c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain[j, i] = plainMatrix[c];
                    c++;
                }
            }

            string[,] roundText = AddRKeyStep(plain, arr3D[0]);

            for (int i = 1; i <= 9; i++)
                roundText = Round(roundText, arr3D[i], false);

            string[,] final = Round(roundText, arr3D[10], true);

            if (!upperCase)
            {
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        final[i, j] = final[i, j].ToLower();
            }

            string cipherText = "";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherText += final[j, i];

            string cipher = "0x" + cipherText.ToString();
            return cipher;
        }

    }
}
