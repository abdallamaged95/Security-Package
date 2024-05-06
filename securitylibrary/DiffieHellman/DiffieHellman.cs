using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>() { 0, 0 };
            int ya = PowerModulo(alpha, xa, q);
            int yb = PowerModulo(alpha, xb, q);
            keys[0] = PowerModulo(yb, xa, q);
            keys[1] = PowerModulo(ya, xb, q);
            return keys;
        }

        public int PowerModulo(int b, int p, int m)
        {
            if (p == 1)
                return b % m;
            return (PowerModulo(b, p - 1, m) * b) % m;
        }
    }
}
