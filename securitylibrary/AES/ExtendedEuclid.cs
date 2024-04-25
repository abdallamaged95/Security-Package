using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int x = 0, y = 0;
            int g = ExtGcd(number, baseN, ref x, ref y);
            if (g != 1)
                return -1;
            int c = ((x % baseN) + baseN) % baseN;
            return c;
        }

        public int ExtGcd(int a, int b, ref int x, ref int y)
        {
            if (b == 0)
            {
                x = 1;
                y = 0;
                return a;
            }
            int g = ExtGcd(b, a % b, ref x, ref y);
            int tmp = x;
            x = y;
            y = tmp - ((a / b) * x);
            return g;
        }
    }
}
