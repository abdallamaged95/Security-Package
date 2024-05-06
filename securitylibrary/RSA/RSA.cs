using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        List<int> GetSums(int x)
        {
            int number = x;
            int divisor = 2;
            List<int> result = new List<int>();

            while (number >= divisor)
            {
                result.Add(2);
                number -= divisor;
            }

            if (number > 0)
            {
                result.Add(number);
            }
            return result;

        }
        int EE(int b, int m)
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
                    var x = B2 % m;
                    if (x < 0)
                    {
                        x += m;
                        return x;
                    }
                    return x;

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
        public int Encrypt(int p, int q, int M, int e)
        {
            var primes=GetSums(e);
            long result = (long)Math.Pow(M, primes[0]) % (p * q);

            for (int i = 1; i < primes.Count; i++)
            {
                if (result > (p * q))
                    result = result % (p * q);
                result *= (long)Math.Pow(M, primes[i]) % (p * q);
            }
                if (result > (p * q))
                    result = result % (p * q);

                return (int)result;
            }

        public int Decrypt(int p, int q, int C, int e)
        {
            var d = EE(e, (p-1) * (q-1));
           var res= Encrypt(p, q, C, d);
            return res;

        }
    }
}
