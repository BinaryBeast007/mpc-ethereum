package me.ausafrashid.sss_mpc;

import com.codahale.shamir.Scheme;
import org.web3j.crypto.*;
import org.web3j.crypto.Sign.SignatureData;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;

public class CryptoManager {
    private Bip39Wallet wallet;
    private Scheme scheme;
    private Map<Integer, byte[]> privateKeyShares;
    private Map<Integer, byte[]> reconstructedShares;
    private String publicKey;
    private SignatureData signature;
    private String message;

    public CryptoManager() {
        privateKeyShares = new HashMap<>();
        reconstructedShares = new HashMap<>();
    }

    public static void main(String[] args) throws IOException, CipherException, InterruptedException, ExecutionException {
        CryptoManager manager = new CryptoManager();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.print("(MAIN) MPC>>");
            String command = scanner.nextLine().trim().toLowerCase();

            switch (command) {
                case "quit":
                case "q":
                case "exit":
                    return;
                case "generate eth wallet":
                    manager.generateWallet(scanner);
                    break;
                case "help":
                case "man":
                    // TBD Manual
                    break;
                case "sign":
                    manager.signMessage(scanner);
                    break;
                case "validate":
                    manager.validateSignature();
                    break;
                default:
                    System.out.println("Command not found. Try running 'help' to learn more.");
            }
        }
    }

    private void generateWallet(Scanner scanner) throws CipherException, IOException {
        System.out.print("Enter Password for Wallet:");
        String walletPassword = scanner.nextLine().trim();
        WalletGenerator generator = new WalletGenerator();
        wallet = generator.generate(walletPassword);
        System.out.println("Ethereum Wallet Generated Successfully!");

        Credentials credentials = WalletUtils.loadBip39Credentials(walletPassword, wallet.getMnemonic());
        String privateKey = credentials.getEcKeyPair().getPrivateKey().toString(Constants.RADIX);

        publicKey = credentials.getEcKeyPair().getPublicKey().toString(Constants.RADIX);

        System.out.println("Main Private Key: " + privateKey);
        System.out.println("Initiating Private Key Splitting");
        System.out.println("n: Number of shares");
        System.out.println("k: Threshold for signing");
        System.out.println("Enter n,k =");
        String nkString = scanner.nextLine();
        String[] nkStringArr = nkString.split(",");
        int n = Integer.parseInt(nkStringArr[0]);
        int k = Integer.parseInt(nkStringArr[1]);

        scheme = new Scheme(new SecureRandom(), n, k);
        privateKeyShares = scheme.split(privateKey.getBytes(StandardCharsets.UTF_8));

        // Displaying all the shares
        System.out.println("Private Keys for all shares:");
        for (int i = 1; i <= n; i++) {
            System.out.println("for share=" + i + ":" + Base64.getEncoder().encodeToString(privateKeyShares.get(i)));
        }
        System.out.println("Minimum Threshold(k) = " + k);
    }

    private void signMessage(Scanner scanner) {
        if (wallet == null) {
            System.out.println("Please generate an Ethereum wallet first!");
            return;
        }

        String[] shareArr = scanner.nextLine().substring(5).split(",");
        if (shareArr.length < scheme.k()) {
            System.out.println("Not enough users signed!");
            return;
        }

        for (int i = 1; i <= shareArr.length; i++) {
            reconstructedShares.put(i, privateKeyShares.get(i));
        }

        byte[] recoveredSecret = scheme.join(reconstructedShares);

        System.out.println("Key Recovery Successful!");
        String recoveredSecretString = new String(recoveredSecret, StandardCharsets.UTF_8);
        System.out.println("Private Key=" + recoveredSecretString);
        System.out.println("Enter signing message =");
        message = scanner.nextLine();

        ECKeyPair pair = new ECKeyPair(new BigInteger(recoveredSecretString, Constants.RADIX), new BigInteger(publicKey, Constants.RADIX));
        signature = Sign.signMessage(message.getBytes(StandardCharsets.UTF_8), pair);
    }

    private void validateSignature() {
        try {
            String pubKey = Sign.signedMessageToKey(message.getBytes(StandardCharsets.UTF_8), signature).toString(Constants.RADIX);
            System.out.println("PubKey=" + pubKey);
            System.out.println("publicKey=" + publicKey);
            if (pubKey.equals(publicKey)) {
                System.out.println("Signature Verification Successful!");
            }
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }
}

class WalletGenerator {
    public Bip39Wallet generate(String walletPassword) throws CipherException, IOException {
        File walletDirectory = new File(Constants.PATH);
        return WalletUtils.generateBip39Wallet(walletPassword, walletDirectory);
    }
}

// class Constants {
//     static final String PATH = "src//main//resources";
//     static final int RADIX = 16;
// }
