package dev.arpan.sphincs;

import org.knowm.xchart.CategoryChart;
import org.knowm.xchart.CategoryChartBuilder;
import org.knowm.xchart.BitmapEncoder;
import org.knowm.xchart.style.Styler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Charts {
    /**
     * Render a bar chart of SPHINCS+ signature sizes from CSV.
     *
     * @param csvPath    path to the CSV file with columns: name, publicKeyBytes, privateKeyBytes, signatureBytes, ...
     * @param outputPath path to output PNG file
     * @throws IOException if reading or writing files fails
     */
    public static void renderSignatureSizeChart(String csvPath, String outputPath) throws IOException {
        // Read CSV lines skipping header
        List<String[]> rows = Files.lines(Paths.get(csvPath))
                .skip(1)
                .map(line -> line.split(","))
                .collect(Collectors.toList());

        List<String> names = new ArrayList<>();
        List<Integer> sigSizes = new ArrayList<>();
        for (String[] row : rows) {
            if (row.length < 4) continue;
            names.add(row[0]);
            try {
                sigSizes.add(Integer.parseInt(row[3].trim()));
            } catch (NumberFormatException e) {
                sigSizes.add(0);
            }
        }

        // Create chart
        CategoryChart chart = new CategoryChartBuilder()
                .width(800)
                .height(600)
                .title("SPHINCS+ Signature Sizes")
                .xAxisTitle("Parameter Set")
                .yAxisTitle("Signature Size (bytes)")
                .build();
        chart.addSeries("Signature Size", names, sigSizes);
        chart.getStyler().setLegendVisible(false);
        chart.getStyler().setHasAnnotations(true);
        chart.getStyler().setPlotGridLinesVisible(false);
        chart.getStyler().setAvailableSpaceFill(0.8);

        // Save chart as PNG
        BitmapEncoder.saveBitmap(chart, outputPath, BitmapEncoder.BitmapFormat.PNG);
    }
}
