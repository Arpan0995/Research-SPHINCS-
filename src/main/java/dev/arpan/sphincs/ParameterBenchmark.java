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
import java.util.List;
import java.util.Locale;
import java.util.zip.Deflater;

/**
 * Benchmark various SPHINCS+ parameter sets for key lengths, signature length, and timing.
 */
public class ParameterBenchmark {

    /**
     * List of parameter sets to benchmark.  Both SHAKE and SHA2 variants are included where applicable.
     */
    private static final List<SPHINCSPlusParameters> PARAM_SETS = List.of(
            SPHINCSPlusParameters.shake_128s,
            SPHINCSPlusParameters.shake_128f,
            SPHINCSPlusParameters.shake_192s,
            SPHINCSPlusParameters.shake_192f,
            SPHINCSPlusParameters.shake_256s,
            SPHINCSPlusParameters.shake_256f,
            SPHINCSPlusParameters.sha2_128s,
            SPHINCSPlusParameters.sha2_128f
    );

    /**
     * Run the benchmark for all configured parameter sets and write results into a CSV in the given output directory.
     * A bar chart of signature sizes is also generated if the XChart library is available.
     *
     * @param outDir the directory where result files should be written
     * @throws IOException if writing to the filesystem fails
     */
    public static void runAll(Path outDir) throws IOException {
        Path csv = outDir.resolve("sphincs_param_bench.csv");
        Files.writeString(csv, "param,pk_bytes,sk_bytes,sig_bytes,sign_ms,verify_ms,gzip_sig_bytes\n");

        byte[] message = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

        for (SPHINCSPlusParameters params : PARAM_SETS) {
            BenchResult result = benchmarkSingle(params, message);
            String row = String.format(Locale.ROOT,
                    "%s,%d,%d,%d,%.3f,%.3f,%d%n",
                    result.name,
                    result.pkLen,
                    result.skLen,
                    result.sigLen,
                    result.signMs,
                    result.verifyMs,
                    result.sigGzipLen);
            Files.writeString(csv, row, java.nio.file.StandardOpenOption.APPEND);
            System.out.printf(Locale.ROOT,
                    "%-24s pk=%5d  sk=%5d  sig=%6d  sign=%.2f ms  verify=%.2f ms  gzip(sig)=%d bytes\n",
                    result.name,
                    result.pkLen,
                    result.skLen,
                    result.sigLen,
                    result.signMs,
                    result.verifyMs,
                    result.sigGzipLen);
        }

        // Attempt to generate a bar chart of signature sizes.  If XChart is unavailable at runtime
        // (e.g. the dependency was excluded), this will catch the error and skip chart generation.
        try {
            Charts.renderSignatureSizeChart(csv, outDir.resolve("sig_sizes.png"));
        } catch (Throwable t) {
            System.err.println("Skipping chart generation: " + t.getMessage());
        }
    }

    /**
     * Holds the results of a single benchmark invocation.
     * @param name the human‑readable name of the parameter set
     * @param pkLen length of the encoded public key in bytes
     * @param skLen length of the encoded secret key in bytes
     * @param sigLen length of the signature in bytes
     * @param signMs signing time in milliseconds
     * @param verifyMs verification time in milliseconds
     * @param sigGzipLen length of the signature when compressed with gzip (for illustration)
     */
    private record BenchResult(String name, int pkLen, int skLen, int sigLen, double signMs, double verifyMs, int sigGzipLen) {}

    /**
     * Benchmark a single parameter set using a fixed message.
     *
     * @param params the SPHINCS+ parameter set to use
     * @param message the message to sign
     * @return a BenchResult containing lengths and timings
     */
    private static BenchResult benchmarkSingle(SPHINCSPlusParameters params, byte[] message) {
        // Key generation
        SPHINCSPlusKeyPairGenerator kpg = new SPHINCSPlusKeyPairGenerator();
        kpg.init(new SPHINCSPlusKeyGenerationParameters(new java.security.SecureRandom(), params));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        SPHINCSPlusPrivateKeyParameters sk = (SPHINCSPlusPrivateKeyParameters) kp.getPrivate();
        SPHINCSPlusPublicKeyParameters pk = (SPHINCSPlusPublicKeyParameters) kp.getPublic();

        // Signing
        SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
        signer.init(true, sk);
        long t0 = System.nanoTime();
        byte[] signature = signer.generateSignature(message);
        long t1 = System.nanoTime();

        // Verification
        SPHINCSPlusSigner verifier = new SPHINCSPlusSigner();
        verifier.init(false, pk);
        long v0 = System.nanoTime();
        boolean ok = verifier.verifySignature(message, signature);
        long v1 = System.nanoTime();
        if (!ok) {
            throw new IllegalStateException("Signature failed to verify for parameters " + params.getName());
        }

        int pkLen = pk.getEncoded().length;
        int skLen = sk.getEncoded().length;
        int sigLen = signature.length;
        double signMs = (t1 - t0) / 1e6;
        double verifyMs = (v1 - v0) / 1e6;
        int gzLen = gzipSize(signature);

        return new BenchResult(params.getName(), pkLen, skLen, sigLen, signMs, verifyMs, gzLen);
    }

    /**
     * Compress the signature using gzip to illustrate that SPHINCS+ signatures are essentially
     * incompressible (compressed size will be similar to uncompressed size plus overhead).
     */
    private static int gzipSize(byte[] data) {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream gos = new java.util.zip.GZIPOutputStream(baos) {{
            def.setLevel(Deflater.BEST_COMPRESSION);
        }}) {
            gos.write(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return baos.toByteArray().length;
    }
}
