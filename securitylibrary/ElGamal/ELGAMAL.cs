using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long c1 = PowerModulo(alpha, k, q);
            long c2 = ((m % q) * PowerModulo(y, k, q)) % q;
            List<long> cipher = new List<long>() { c1, c2 };
            return cipher;
        }
     
        public int Decrypt(int c1, int c2, int x, int q)
        {

            int tmp = PowerModulo(c1, q - 1 - x, q);
            int plain = (c2 * tmp) % q;
            return plain;
        }

        public int PowerModulo(int b, int p, int m)
        {
            if (p == 1)
                return b % m;
            return (PowerModulo(b, p - 1, m) * b) % m;
        }
    }
}
