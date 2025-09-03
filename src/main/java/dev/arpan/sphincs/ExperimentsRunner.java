package dev.arpan.sphincs;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Entrypoint class that runs all experiments and writes output to the results directory.
 */
public class ExperimentsRunner {
    public static void main(String[] args) throws Exception {
        Path outDir = Path.of("results");
        Files.createDirectories(outDir);

        System.out.println("Running SPHINCS+ parameter benchmarks...");
        ParameterBenchmark.runAll(outDir);

        System.out.println();
        System.out.println("Running Merkle batch signing demo...");
        MerkleBatchSigner.demo(outDir);

        System.out.println();
        System.out.println("Finished. See the 'results' directory for output files.");
    }
}
