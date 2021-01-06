package com.tracelink.appsec.ariadne;

import com.opencsv.CSVReader;
import com.tracelink.appsec.ariadne.mock.LoggerRule;
import java.io.File;
import java.io.FileReader;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

public class AriadneTest {

	private static final String RESOURCES = "src/test/resources/";

	@Rule
	public LoggerRule loggerRule = LoggerRule.forClass(Ariadne.class);

	@After
	public void clean() {
		File output = new File(RESOURCES + "output");
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
				"-d", "mvn-tree", RESOURCES + "trees/dependency-tree.txt",
				"-v", "nexus-iq-vios", RESOURCES + "vulnerability/violations.csv",
				"-w", "csv", RESOURCES + "output/",
				"-i", "com.example",
				"--stats"
		});

		try (CSVReader csvReader = new CSVReader(
				new FileReader(RESOURCES + "output/tiers.csv"))) {
			List<String[]> lines = csvReader.readAll();
			Assert.assertTrue(lines.stream().anyMatch(line ->
					line[0].equals("com.example:project-a") && line[1].equals("1")));
			Assert.assertTrue(lines.stream().anyMatch(line ->
					line[0].equals("com.example:project-b") && line[1].equals("0")));
		}

		// Check that stats were written
		Assert.assertTrue(new File(RESOURCES + "output/dependencies.csv").exists());
		Assert.assertTrue(new File(RESOURCES + "output/vulnerabilities.csv").exists());
		// Check that all stages were logged
		Assert.assertTrue(
				loggerRule.getMessages().contains("Reading dependencies and vulnerabilities"));
		Assert.assertTrue(loggerRule.getMessages().contains("Analyzing data"));
		Assert.assertTrue(loggerRule.getMessages().contains("Writing stats"));
		Assert.assertTrue(loggerRule.getMessages().contains("Writing tiers"));
	}

	@Test
	public void testAriadneBadFile() {
		Ariadne.main(new String[]{
				"-d", "mvn-tree", "foo.txt",
				"-v", "nexus-iq-vios", RESOURCES + "vulnerability/violations.csv",
				"-w", "csv", RESOURCES + "output/",
				"-i", "com.example"
		});

		Assert.assertTrue(loggerRule.getMessages().isEmpty());
	}

	@Test
	public void testAriadneMalformedTreeException() {
		Ariadne.main(new String[]{
				"-d", "mvn-tree", RESOURCES + "trees/simple-tree.txt",
				"-v", "nexus-iq-vios", RESOURCES + "vulnerability/malformed-violations.csv",
				"-w", "csv", RESOURCES + "output/",
				"-i", "com.example"
		});
		Assert.assertEquals("Exception occurred during analysis",
				loggerRule.getMessages().get(loggerRule.getMessages().size() - 1));
	}
}
