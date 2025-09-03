package dev.arpan.sphincs;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Demonstrates how to amortize the cost of a SPHINCS+ signature by signing many messages together
 * in a Merkle tree.  Each message's inclusion proof consists of log₂(N) sibling hashes.  The
 * average per‑message overhead is (sig_bytes / N) + (log₂(N) × hash_len).
 */
public class MerkleBatchSigner {

    /**
     * A simple binary tree node.  Inner node hashes are computed as SHA‑256(left || right).
     */
    private static class Node {
        byte[] hash;
        Node left;
        Node right;
        Node(byte[] hash) {
            this.hash = hash;
        }
        Node(Node left, Node right) {
            this.left = left;
            this.right = right;
            this.hash = hashConcat(left.hash, right.hash);
        }
    }

    /**
     * Represents an inclusion proof for a leaf.  The list contains the sibling hashes from leaf to root.
     */
    private static class Proof {
        final int index;
        final List<byte[]> authPath;
        Proof(int index, List<byte[]> authPath) {
            this.index = index;
            this.authPath = authPath;
        }
    }

    /**
     * Execute the Merkle batching demo.  Writes a CSV summary and an explanatory text file to the output directory.
     *
     * @param outDir the directory where result files should be written
     * @throws IOException if writing fails
     */
    public static void demo(Path outDir) throws IOException {
        int batchSize = 64;
        List<byte[]> messages = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            messages.add(("message-" + i).getBytes(StandardCharsets.UTF_8));
        }

        // Build the Merkle tree using SHA‑256 hashes of each message
        List<byte[]> leaves = new ArrayList<>();
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        for (byte[] m : messages) {
            leaves.add(md.digest(m));
        }
        Node root = buildTree(leaves);
        byte[] rootHash = root.hash;

        // Generate a SPHINCS+ keypair (use 128s for small signature demonstration)
        SPHINCSPlusParameters params = SPHINCSPlusParameters.shake_128s;
        SPHINCSPlusKeyPairGenerator kpg = new SPHINCSPlusKeyPairGenerator();
        kpg.init(new SPHINCSPlusKeyGenerationParameters(new java.security.SecureRandom(), params));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        SPHINCSPlusPrivateKeyParameters sk = (SPHINCSPlusPrivateKeyParameters) kp.getPrivate();
        SPHINCSPlusPublicKeyParameters pk = (SPHINCSPlusPublicKeyParameters) kp.getPublic();

        SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
        signer.init(true, sk);
        byte[] signature = signer.generateSignature(rootHash);

        // Generate inclusion proofs for each message
        List<Proof> proofs = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            proofs.add(getProof(i, leaves));
        }

        // Compute the per‑message overhead: signature amortized over N messages + proof size
        int sigBytes = signature.length;
        int proofBytes = proofs.get(0).authPath.size() * 32; // each sibling hash is 32 bytes (SHA‑256)
        double perMsg = (sigBytes * 1.0 / batchSize) + proofBytes;

        // Write summary CSV
        Path summaryCsv = outDir.resolve("merkle_batching_summary.csv");
        Files.writeString(summaryCsv, "batch_size,sig_bytes,proof_bytes_per_msg,avg_overhead_per_msg_bytes\n");
        String row = String.format(java.util.Locale.ROOT, "%d,%d,%d,%.2f\n", batchSize, sigBytes, proofBytes, perMsg);
        Files.writeString(summaryCsv, row, java.nio.file.StandardOpenOption.APPEND);

        // Write a brief explanation file
        Path note = outDir.resolve("MERKLE_BATCH_EXPLANATION.txt");
        String text = "This demo signs a batch of messages by hashing them into a binary Merkle tree (SHA-256) "
                + "and signing only the root using the SPHINCS+-128s parameter set.\n"
                + "Each message carries (a) the shared SPHINCS+ signature on the root and (b) its authentication path, which "
                + "contains log2(N) 32-byte hashes. The average per-message overhead is (signature_length / N) + (log2(N) * 32).\n";
        Files.writeString(note, text);
    }

    // Build the Merkle tree bottom‑up, duplicating the last node if the layer has an odd number of nodes
    private static Node buildTree(List<byte[]> leaves) {
        List<Node> layer = new ArrayList<>();
        for (byte[] h : leaves) {
            layer.add(new Node(h));
        }
        while (layer.size() > 1) {
            List<Node> next = new ArrayList<>();
            for (int i = 0; i < layer.size(); i += 2) {
                Node left = layer.get(i);
                Node right = (i + 1 < layer.size()) ? layer.get(i + 1) : left;
                next.add(new Node(left, right));
            }
            layer = next;
        }
        return layer.get(0);
    }

    // Compute the inclusion proof for the leaf at index idx
    private static Proof getProof(int idx, List<byte[]> leaves) {
        List<Node> layer = new ArrayList<>();
        for (byte[] h : leaves) {
            layer.add(new Node(h));
        }
        List<byte[]> auth = new ArrayList<>();
        int index = idx;
        while (layer.size() > 1) {
            List<Node> next = new ArrayList<>();
            for (int i = 0; i < layer.size(); i += 2) {
                Node left = layer.get(i);
                Node right = (i + 1 < layer.size()) ? layer.get(i + 1) : left;
                next.add(new Node(left, right));
            }
            int sibling = (index % 2 == 0) ? index + 1 : index - 1;
            if (sibling >= layer.size()) {
                sibling = index; // duplicate last if no sibling
            }
            auth.add(layer.get(sibling).hash);
            index /= 2;
            layer = next;
        }
        return new Proof(idx, auth);
    }

    // Compute SHA‑256(left || right)
    private static byte[] hashConcat(byte[] a, byte[] b) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(a);
            md.update(b);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
