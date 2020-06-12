package fr.epsi.jconte;

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

public class RSA {

    // public = (N, e)
    // privée = (N, d)

    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 1024;
    private Random r;

    public RSA() {

        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 2, r);

        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {

            e.add(BigInteger.ONE);
        }

        d = e.modInverse(phi);
    }

    public RSA(BigInteger e, BigInteger d, BigInteger N) {

        this.e = e;
        this.d = d;
        this.N = N;
    }

    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws IOException {

        RSA rsa = new RSA();
        //RSA rsa = new RSA(BigInteger.valueOf(7), BigInteger.valueOf(23), BigInteger.valueOf(187));

        DataInputStream in = new DataInputStream(System.in);

        String teststring;

        System.out.println("Enter the plain text:");

        teststring = in.readLine();

        System.out.println("Encrypting String: " + teststring);

        System.out.println("String in Bytes: " + bytesToString(teststring.getBytes()));

        // encrypt
        byte[] encrypted = rsa.encrypt(teststring.getBytes());

        // decrypt
        byte[] decrypted = rsa.decrypt(encrypted);

        System.out.println("Decrypting Bytes: " + bytesToString(decrypted));

        System.out.println("Decrypted String: " + new String(decrypted));
    }


    private static String bytesToString(byte[] encrypted) {

        String test = "";

        for (byte b : encrypted) {

            test += Byte.toString(b);
        }

        return test;
    }


    // Encrypt message
    public byte[] encrypt(byte[] message) {

        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }

    // Decrypt message
    public byte[] decrypt(byte[] message) {

        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }

    int gcdByEuclidsAlgorithm(int n1, int n2) {
        if (n2 == 0) {
            return n1;
        }
        return gcdByEuclidsAlgorithm(n2, n1 % n2);
    }

    int modInverse(int a, int m) {
        int m0 = m;
        int y = 0, x = 1;

        if (m == 1)
            return 0;

        while (a > 1) {
            // q is quotient
            int q = a / m;

            int t = m;

            // m is remainder now, process
            // same as Euclid's algo
            m = a % m;
            a = t;
            t = y;

            // Update x and y
            y = x - q * y;
            x = t;
        }

        // Make x positive
        if (x < 0)
            x += m0;

        return x;
    }
}