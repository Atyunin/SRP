import java.math.BigInteger;
import java.util.Random;

class PrimeNum
{
    int maxNumber = 10000;

    private Random random = new Random();

    public int GetPrimeNumber()
    {
        int value = random.nextInt(maxNumber);

        while (test(value) == false)
            value = random.nextInt(maxNumber);

        return value;
    }

    static boolean test(long n) {

        long r =  (long) (Math.log10(n) / Math.log10(2));
        long s = 0;

        long t = n-1;

        while (true) {

            if ((t%2) == 0) {

                t = t / 2;
                s++;
            } else {

                break;
            }
        }

        A: for (int i = 0; i < r; i++) {



            Long a = (long) ((Math.random() * (n-4)) + 2);

            BigInteger x = new BigInteger(Long.toString(a));
            x = x.modPow(new BigInteger(Long.toString(t)), new BigInteger(Long.toString(n)));

            if ((x.equals(new BigInteger(Long.toString(1)))) || (x.equals(new BigInteger(Long.toString(n-1)))))
                continue;

            for (int j = 0; j < (s - 1); j++) {

                x =  x.modPow(new BigInteger(Long.toString(2)), new BigInteger(Long.toString(n)));

                if (x.equals(new BigInteger(Long.toString(1)))) {

                    return false;
                }
                if (x.equals(new BigInteger(Long.toString(n-1)))) {

                    continue A;
                }
            }

            return false;
        }

        return true;
    }
}