package com.tracelink.appsec.ariadne;

import com.opencsv.CSVReader;
import java.io.File;
import java.io.FileReader;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

public class TestAriadne {

	@After
	public void clean() {
		File output = new File("src/test/resources/output");
		File[] files = output.listFiles();
		if (files != null) {
			for (File file : files) {
				file.delete();
			}
		}
		output.delete();
	}

	@Test
	public void testAriadne() throws Exception {
		Ariadne.main(new String[]{
				"-d", "mvn-tree", "src/test/resources/dependency-tree.txt",
				"-v", "nexus-iq-vios", "src/test/resources/violations.csv",
				"-w", "csv", "src/test/resources/output/",
				"-i", "com.example"
		});

		try (CSVReader csvReader = new CSVReader(
				new FileReader("src/test/resources/output/tiers.csv"))) {
			List<String[]> lines = csvReader.readAll();
			Assert.assertTrue(lines.stream().anyMatch(line ->
					line[0].equals("com.example:project-a") && line[1].equals("1")));
			Assert.assertTrue(lines.stream().anyMatch(line ->
					line[0].equals("com.example:project-b") && line[1].equals("0")));
		}
	}

	@Test
	public void testAriadneBadFile() {
		Ariadne.main(new String[]{
				"-d", "mvn-tree", "foo.txt",
				"-v", "nexus-iq-vios", "src/test/resources/violations.csv",
				"-w", "csv", "src/test/resources/output/",
				"-i", "com.example"
		});
	}
}
