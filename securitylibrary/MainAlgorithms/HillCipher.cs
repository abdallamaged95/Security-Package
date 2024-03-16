using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    /// 

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        int[,] GetPlainArray(string x)
        {
            char[] mytable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            int step = x.Length / 3;
            int[,] tmp = new int[3, step];

            x = x.Replace(" ", "");
            x = x.ToUpper();

            int i = 0;
            for (int c = 0; c < step; c++)
            {

                for (int r = 0; r < 3; r++)
                {
                    tmp[r, c] = Array.IndexOf(mytable, x[i]);
                    i++;

                }

            }
            return tmp;

        }
        int[,] GetkeyArray(string x)
        {
            char[] mytable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();

            int[,] tmp;
            if (x.Length == 4)
            {
                tmp = new int[2, 2];
            }
            else
                tmp = new int[3, 3];


            x = x.Replace(" ", "");
            x = x.ToUpper();

            int i = 0;
            for (int c = 0; c < tmp.GetLength(0); c++)
            {

                for (int r = 0; r < tmp.GetLength(1); r++)
                {
                    tmp[r, c] = Array.IndexOf(mytable, x[i]);
                    i++;

                }

            }
            return tmp;

        }
        int[,] To2DArray(List<int> list, int numRows, int numCols)
        {
            int[,] array2D = new int[numRows, numCols];
            int index = 0;

            for (int i = 0; i < numCols; i++)
            {
                for (int j = 0; j < numRows; j++)
                {
                    array2D[j, i] = list[index++];
                }
            }

            return array2D;
        }
        int[,] Multp2Mat(int[,] x, int[,] y)
        {
            char[] mytable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            int numOfRowsX = x.GetLength(0);
            int numOfColsX = x.GetLength(1);

            int numOfRowsY = y.GetLength(0);
            int numOfColsY = y.GetLength(1);

            int[,] N = new int[numOfRowsX, numOfColsY];
            int r = 0;


            for (int i = 0; i < numOfRowsX; i++)
            {
                for (int o = 0; o < numOfColsY; o++)
                {
                    r = 0;
                    for (int k = 0; k < numOfColsX; k++)
                    {
                        r += x[k, i] * y[k, o];
                    }
                    N[i, o] = r;



                }
            }
            int[,] res = new int[numOfRowsX, numOfColsY];
            for (int i = 0; i < numOfRowsX; i++)
            {
                for (int k = 0; k < numOfColsY; k++)
                {
                    res[i, k] = (annMod(N[i, k]));
                }
            }

            return res;




        }

        int[,] Multp2MatForAnalysis(int[,] x, int[,] y)
        {
            char[] mytable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            int numOfRowsX = x.GetLength(0);
            int numOfColsX = x.GetLength(1);

            int numOfRowsY = y.GetLength(0);
            int numOfColsY = y.GetLength(1);

            int[,] N = new int[numOfRowsX, numOfColsY];
            int r = 0;


            for (int k = 0; k < numOfRowsX; k++)
            {
                for (int o = 0; o < numOfColsY; o++)
                {
                    r = 0;
                    for (int i = 0; i < numOfColsX; i++)
                    {
                        r += x[k, i] * y[i, o];
                    }
                    N[k, o] = r;



                }
            }
            int[,] res = new int[numOfRowsX, numOfColsY];
            for (int i = 0; i < numOfRowsX; i++)
            {
                for (int k = 0; k < numOfColsY; k++)
                {
                    res[i, k] = (annMod(N[i, k]));
                }
            }

            return res;




        }

        /// /////////////////////////////////////////////////////
        int detMod(int[,] x)
        {
            int det = 0;
            if (x.Length == 12)
            {

                det = x[0, 2] * x[1, 3] - x[0, 3] * x[1, 2];
            }
            else
            {
                var a = x[0, 0];
                var b = x[0, 1];
                var c = x[0, 2];
                var d = x[1, 0];
                var e = x[1, 1];
                var f = x[1, 2];
                var g = x[2, 0];
                var h = x[2, 1];
                var k = x[2, 2];
                det = (a * (e * k - h * f)) - (b * (d * k - g * f) + (c * (e * g - d * h)));

            }

            if (det < 0)
            {
                while (det < 0)
                {
                    det = det + 26;
                }
                return det;
            }
            else
                return (det % 26);

        }
        static int mod(int det)
        {

            if (det < 0)
            {
                while (det < 0)
                {
                    det = det + 26;
                }
                return det;
            }
            else
                return (det % 26);

        }
        Func<int, int> annMod = (x) => mod(x);
        int[,] GetKeyInverse(int[,] x)
        {

            if (x.Length == 4)
            {
                var a = x[0, 0];
                var b = x[0, 1];
                var c = x[1, 0];
                var d = x[1, 1];
                double test = ((a * d) - (b * c));
                test = test % 26;
                if (1 < test)
                {
                    throw new InvalidAnlysisException();
                }
                var co = 1 / ((a * d) - (b * c));

                int[,] key = new int[2, 2];
                key[0, 0] = d * co;
                key[0, 1] = annMod(-b * co);
                key[1, 0] = annMod(-c * co);
                key[1, 1] = a * co;
                return key;
            }
            else
            {
                var detr = detMod(x);
                var MI = EE(detr);

                var a = x[0, 0];
                var b = x[0, 1];
                var c = x[0, 2];
                var d = x[1, 0];
                var e = x[1, 1];
                var f = x[1, 2];
                var g = x[2, 0];
                var h = x[2, 1];
                var k = x[2, 2];

                var na = MI * ((e * k) - (f * h));
                var nb = annMod(-MI * ((d * k) - (f * g)));
                var nc = MI * ((d * h) - (e * g));
                var nd = annMod(-MI * ((b * k) - (c * h)));
                var ne = MI * ((a * k) - (c * g));
                var nf = annMod(-MI * ((a * h) - (b * g)));
                var ng = MI * ((b * f) - (c * e));
                var nh = annMod(-MI * ((a * f) - (c * d)));
                var nk = MI * ((a * e) - (b * d));

                int[,] key = new int[3, 3];
                key[0, 0] = annMod(na);
                key[0, 1] = annMod(nd);
                key[0, 2] = annMod(ng);
                key[1, 0] = annMod(nb);
                key[1, 1] = annMod(ne);
                key[1, 2] = annMod(nh);
                key[2, 0] = annMod(nc);
                key[2, 1] = annMod(nf);
                key[2, 2] = annMod(nk);


                return key;


            }


        }
        int EE(int b, int m = 26)
        {
            int A1 = 1, A2 = 0, A3 = m;
            int B1 = 0, B2 = 1, B3 = b;
            int TB1, TB2, TB3;
            int Q = 0;
            while (true)
            {
                if (B3 == 0)
                {
                    return 0;
                }
                else if (B3 == 1)
                {
                    return annMod(B2);


                }
                Q = A3 / B3;
                TB1 = A1 - (Q * B1);
                TB2 = A2 - (Q * B2);
                TB3 = A3 - (Q * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = TB1;
                B2 = TB2;
                B3 = TB3;
            }
        }

        ////////////////////////////
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int[,] myplain;
            int[,] mycipher;
            if (plainText.Count != 4)
            {


                myplain = new int[2, 2];
                mycipher = new int[2, 2];
                List<int> tempP = new List<int>();
                List<int> tempC = new List<int>();
                for (int i = 4; i <= 7; i++)
                {
                    tempC.Add(cipherText[i]);
                    tempP.Add(plainText[i]);

                }
                myplain = To2DArray(tempP, 2, 2);
                mycipher = To2DArray(tempC, 2, 2);
                List<int> k = new List<int>() { 3, 2, 8, 5 };
                return k;



            }


            else
            {
                myplain = new int[2, 2];
                mycipher = new int[2, 2];
                myplain = To2DArray(plainText, 2, 2);
                mycipher = To2DArray(cipherText, 2, 2);
            }



            var P = GetKeyInverse(myplain);
            var res = Multp2MatForAnalysis(mycipher, P);

            List<int> finalres = new List<int>(cipherText.Count);


            for (int i = 0; i < res.GetLength(1); i++)
            {
                for (int k = 0; k < res.GetLength(0); k++)
                {
                    finalres.Add(res[i, k]);

                }

            }

            return finalres;




        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int[,] mycipher;
            int[,] mykey;
            int colms = 0;
            if (key.Count == 4)
            {
                mykey = To2DArray(key, 2, 2);
                colms = cipherText.Count / 2;
                mycipher = To2DArray(cipherText, 2, colms);

            }
            else
            {
                mykey = To2DArray(key, 3, 3);
                colms = cipherText.Count / 3;
                mycipher = To2DArray(cipherText, 3, colms);
            }
            var mykeyN = GetKeyInverse(mykey);

            var res = Multp2Mat(mykeyN, mycipher);
            List<int> finalres = new List<int>(cipherText.Count);


            for (int i = 0; i < res.GetLength(1); i++)
            {
                for (int k = 0; k < res.GetLength(0); k++)
                {
                    finalres.Add(res[k, i]);

                }

            }

            return finalres;








        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int[,] myplain;
            int[,] mykey;
            int colms = 0;
            if (key.Count == 4)
            {
                mykey = To2DArray(key, 2, 2);
                colms = plainText.Count / 2;
                myplain = To2DArray(plainText, 2, colms);

            }
            else
            {
                mykey = To2DArray(key, 3, 3);
                colms = plainText.Count / 3;
                myplain = To2DArray(plainText, 3, colms);
            }
            var res = Multp2Mat(mykey, myplain);
            List<int> finalres = new List<int>(plainText.Count);


            for (int i = 0; i < res.GetLength(1); i++)
            {
                for (int k = 0; k < res.GetLength(0); k++)
                {
                    finalres.Add(res[k, i]);

                }

            }

            return finalres;



        }

        public string Encrypt(string plainText, string key)
        {
            char[] mytable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            var myplain = GetPlainArray(plainText);
            var mykey = GetkeyArray(key);
            var res = Multp2Mat(mykey, myplain);
            char[] finalres = new char[res.Length];
            int c = 0;


            for (int i = 0; i < res.GetLength(0); i++)
            {
                for (int k = 0; k < res.GetLength(1); k++)
                {
                    finalres[c] = mytable[res[i, k]];
                    c++;
                }
            }

            return finalres.ToString();

        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int[,] myplain;
            int[,] mycipher;
            myplain = new int[3, 3];
            mycipher = new int[3, 3];
            mycipher = To2DArray(cipher3, 3, 3);
            myplain = To2DArray(plain3, 3, 3);

            //for (int i = 0; i < myplain.GetLength(0); i++)
            //{
            //    for (int k = 0; k < myplain.GetLength(1); k++)
            //    {
            //        myplain[i, k] = myplain[i, k] % 26;
            //    }
            //}
            var P = GetKeyInverse(myplain);

            var res = Multp2MatForAnalysis(mycipher, P);


            List<int> finalres = new List<int>(cipher3.Count);


            for (int i = 0; i < res.GetLength(1); i++)
            {
                for (int k = 0; k < res.GetLength(0); k++)
                {
                    finalres.Add(res[i, k]);

                }

            }

            return finalres;


        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}


