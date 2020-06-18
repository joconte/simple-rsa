package fr.epsi.jconte;

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;


public class RSA {

    // Clé publique = (N, e)
    // Clé privée = (N, d)

    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 16;
    private Random r;

    public RSA() {

        generationDesClefs();
    }

    private void generationDesClefs() {

        // Génération des clés
        System.out.println("Génération des clefs...");
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 2, r);

        while (gcdByEuclidsAlgorithm(phi.longValue(), e.longValue()) > 1 && e.longValue() < phi.longValue()) {

            e.add(BigInteger.ONE);
        }

        long dLong = modInverse(e.longValue(), phi.longValue());
        d = BigInteger.valueOf(dLong);

        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("N = p * q = " + N);
        System.out.println("phi = (p - 1) * (q - 1) = " + phi);
        System.out.println("e = " + e);
        System.out.println("d = " + d);
        System.out.println("Clé publique : (" + N + ", " + e + ")");
        System.out.println("Clé privée : (" + N + ", " + d + ")");
    }

    private static byte[] preparationDuMessage(String message) {

        byte[] messageInBytes = message.getBytes();
        System.out.println("Transformation du message : " + message + " (String) -> " + bytesToString(messageInBytes) + " (byte[])");

        return messageInBytes;
    }

    public RSA(BigInteger e, BigInteger d, BigInteger N) {

        this.e = e;
        this.d = d;
        this.N = N;
    }

    public static void main(String[] args) throws IOException {

        RSA rsa = new RSA();

        DataInputStream in = new DataInputStream(System.in);

        String messageAChiffrer;

        System.out.println("Entrez le message à chiffrer : ");

        messageAChiffrer = in.readLine();

        byte[] messagePrepare = preparationDuMessage(messageAChiffrer);

        // encrypt
        byte[] messageChiffre = rsa.encrypt(messagePrepare);

        System.out.println("Message chiffré : " + new String(messageChiffre) + " (String)");

        // decrypt
        byte[] messageDechiffre = rsa.decrypt(messageChiffre);

        System.out.println("Message déchiffré : " + new String(messageDechiffre) + " (String)");
    }


    private static String bytesToString(byte[] encrypted) {

        String test = "";

        for (byte b : encrypted) {

            test += Byte.toString(b);
        }

        return test;
    }


    // Chiffrement du message
    public byte[] encrypt(byte[] message) {

        System.out.println("Chiffrage du message...");
        System.out.println("Avant : " + bytesToString(message) + " (byte[])");

        // modPow -> (message ^ e) % N
        byte[] encryptedMessage = (new BigInteger(message)).modPow(e, N).toByteArray();

        System.out.println("Après : " + bytesToString(encryptedMessage) + " (byte[])");

        return encryptedMessage;
    }

    // Déchiffrement du message
    public byte[] decrypt(byte[] message) {

        System.out.println("Dechiffrement du message...");
        System.out.println("Avant : " + bytesToString(message) + " (byte[])");

        // modPow -> (message ^ e) % N
        byte[] clearMessage = (new BigInteger(message)).modPow(d, N).toByteArray();

        System.out.println("Après : " + bytesToString(clearMessage) + " (byte[])");

        return clearMessage;
    }

    long gcdByEuclidsAlgorithm(long n1, long n2) {
        if (n2 == 0) {
            return n1;
        }
        return gcdByEuclidsAlgorithm(n2, n1 % n2);
    }

    long modInverse(long a, long m) {
        long m0 = m;
        long y = 0, x = 1;

        if (m == 1)
            return 0;

        while (a > 1) {
            // q is quotient
            long q = a / m;

            long t = m;

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