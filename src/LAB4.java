import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

public class LAB4 {

    public static void main(String[] args) {

        SRP ("12345");
    }

    static void SRP (String password) {

        PrimeNum prime = new PrimeNum();

        int N = 0;
        int q = 0;
        while (prime.test(N)) {

            q = prime.GetPrimeNumber();
            N = 2*q + 1;
        }

        System.out.println("N = " + N);
        System.out.println("q = " + q);

        int g = 2;

        System.out.println("g = " + g);

        int salt = new Random().nextInt();

        System.out.println("S = " + salt);

        BigInteger x = hash(password + Integer.toString(salt));

        System.out.println("Секретный ключ " + x);

        BigInteger v = new BigInteger(Integer.toString(g)).modPow(x, new BigInteger(Integer.toString(N)));

        System.out.println("Верификатор пароля " + v);

        BigInteger a = new BigInteger(Integer.toString(new Random().nextInt(98) + 2));

        BigInteger A = new BigInteger(Integer.toString(g)).modPow(a, new BigInteger(Integer.toString(N)));

        if (A.intValue() != 0) {
            BigInteger b = new BigInteger(Integer.toString(new Random().nextInt(98) + 2));
            BigInteger k = new BigInteger("3");
            BigInteger B = (k.multiply(v).add(new BigInteger(Integer.toString(g)).modPow(b, new BigInteger(Integer.toString(N)))).mod(new BigInteger(Integer.toString(N))));

            if (B.intValue()!=0) {

                BigInteger u = hash(A.add(B).toString(16));

                if (u.intValue()!=0) {

                    BigInteger client_session_key = B.subtract(k.multiply(new BigInteger(Integer.toString(g)).modPow(x, new BigInteger(Integer.toString(N))))).modPow(a.add(u.multiply(x)), new BigInteger(Integer.toString(N)));
                    BigInteger client_encode_key = hash(client_session_key.toString(16));

                    BigInteger server_session_key = A.multiply(v.modPow(u, new BigInteger(Integer.toString(N)))).modPow(b, new BigInteger(Integer.toString(N)));
                    BigInteger server_encode_key = hash(server_session_key.toString(16));

                    System.out.println("Общий ключ сессии клиента " + client_session_key);
                    System.out.println("Общий ключ сессии сервера " + server_session_key);
                    System.out.println("Искомый ключ для шифрования клиента " + client_encode_key);
                    System.out.println("Искомый ключ для шифрования сервера " + server_encode_key);

                    BigInteger M_client = hash(hash((Integer.toString(N))).xor(hash((Integer.toString(g)))).toString() + Integer.toString(salt) + A.toString() + B.toString() + server_encode_key.toString());
                    BigInteger M_server = hash(hash((Integer.toString(N))).xor(hash((Integer.toString(g)))).toString() + Integer.toString(salt) + A.toString() + B.toString() + client_encode_key.toString());

                    if (M_server.equals(M_client)) {
                        System.out.println("Пользователь подтвержден");
                        BigInteger M1_client = hash(A.toString() + M_client.toString() + client_session_key.toString());
                        BigInteger M1_server = hash(A.toString() + M_server.toString() + server_session_key.toString());
                        if (M1_client.equals(M1_server))
                            System.out.println("Сервер подтвержден");
                        else
                            System.out.println("Соединение прервано");
                    } else {
                        System.out.println("Соединение прервано");
                    }
                }
            }
        }
    }

    static int modPow (int a, int b, int c) {

        return new BigInteger(Integer.toString(a)).modPow(new BigInteger(Integer.toString(b)), new BigInteger(Integer.toString(c))).intValue();
    }

    static int modPow (int a, BigInteger b, int c) {

        return new BigInteger(Integer.toString(a)).modPow(b, new BigInteger(Integer.toString(c))).intValue();
    }


    static BigInteger hash (String val) {


        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] encodedhash = digest.digest(val.getBytes(StandardCharsets.UTF_8));

        String str = bytesToHex(encodedhash);

        str = str.toUpperCase();

        BigInteger num = new BigInteger(str.substring(0, 7), 16);
        return num;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
