package com.tracelink.appsec.ariadne.write;

import com.opencsv.CSVReader;
import com.tracelink.appsec.ariadne.mock.LoggerRule;
import com.tracelink.appsec.ariadne.model.Artifact;
import com.tracelink.appsec.ariadne.model.ExternalArtifact;
import com.tracelink.appsec.ariadne.model.InternalArtifact;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class StandardCsvWriterTest {

	private static final String RESOURCES = "src/test/resources/";
	private List<Artifact> artifacts;

	@Rule
	public LoggerRule loggerRule = LoggerRule.forClass(StandardCsvWriter.class);

	@Before
	public void setup() {
		Artifact projectA = new InternalArtifact("com.example:project-a:1.0.0");
		projectA.addVersion("1.2.3");

		Artifact projectB = new InternalArtifact("com.example:project-b:1.1.1");
		projectB.addParent("1.1.1", projectA);
		projectA.addChild("1.2.3", projectB);

		Artifact libraryC = new ExternalArtifact("org.third.party:library-c:2.0.4");
		libraryC.addParent("2.0.4", projectB);
		projectB.addChild("1.1.1", libraryC);

		Artifact libraryD = new ExternalArtifact("org.third.party:library-d:3.5.1");
		libraryD.addFindings(2);
		libraryD.addParent("3.5.1", libraryC);
		libraryC.addChild("2.0.4", libraryD);
		libraryD.assignTiers();

		Artifact libraryDv2 = new ExternalArtifact("org.third.party:library-d:1.4.7");
		libraryDv2.addFindings(1);

		artifacts = new ArrayList<>();
		artifacts.addAll(Arrays.asList(projectA, projectB, libraryC, libraryD, libraryDv2));
	}

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

	@Test(expected = IllegalArgumentException.class)
	public void testWriterFileAlreadyExists() throws IOException {
		Path temp = null;
		try {
			temp = Files.createTempFile(null, ".xml");
			temp.toFile().createNewFile();
			new StandardCsvWriter(temp.toString());
		} finally {
			if (temp != null) {
				temp.toFile().delete();
			}
		}
	}

	@Test
	public void testWriteDependencies() throws Exception {
		Writer csvWriter = new StandardCsvWriter(RESOURCES + "output/");
		csvWriter.setArtifacts(artifacts);
		csvWriter.writeDependencies();

		try (CSVReader fileReader = new CSVReader(
				new FileReader(RESOURCES + "output/dependencies.csv"))) {
			List<String[]> lines = fileReader.readAll();
			Assert.assertTrue(lines.stream().anyMatch(line ->
					line[0].equals("com.example:project-a")
							&& line[1].equals("0")
							&& line[2].equals("2")));
			Assert.assertTrue(lines.stream().anyMatch(line ->
					line[0].equals("com.example:project-b")
							&& line[1].equals("1")
							&& line[2].equals("1")));
		}
	}

	@Test
	public void testWriteVulnerabilities() throws Exception {
		Writer csvWriter = new StandardCsvWriter(RESOURCES + "output/");
		csvWriter.setArtifacts(artifacts);
		csvWriter.writeVulnerabilities();

		try (CSVReader fileReader = new CSVReader(
				new FileReader(RESOURCES + "output/vulnerabilities.csv"))) {
			List<String[]> lines = fileReader.readAll();
			String[] line1 = lines.get(1);
			Assert.assertEquals("Library D", line1[0]);
			Assert.assertEquals("Total", line1[1]);
			String[] line2 = lines.get(2);
			Assert.assertEquals("org.third.party:library-d:3.5.1", line2[0]);
			Assert.assertEquals("2", line2[1]);
			String[] line3 = lines.get(3);
			Assert.assertEquals("org.third.party:library-d:1.4.7", line3[0]);
			Assert.assertEquals("1", line3[1]);
			String[] line4 = lines.get(4);
			Assert.assertEquals("100.00%", line4[0]);
			Assert.assertEquals("3", line4[1]);

			Assert.assertTrue(lines.stream()
					.noneMatch(line -> Arrays.asList(line).contains("org.third.party:library-c")));
		}
	}

	@Test
	public void testWriteTiers() throws Exception {
		Writer csvWriter = new StandardCsvWriter(RESOURCES + "output/");
		csvWriter.setArtifacts(artifacts);
		csvWriter.writeTiers();

		try (CSVReader fileReader = new CSVReader(
				new FileReader(RESOURCES + "output/tiers.csv"))) {
			List<String[]> lines = fileReader.readAll();
			Assert.assertTrue(lines.stream()
					.anyMatch(line -> line[0].equals("com.example:project-a")
							&& line[1].equals("1")
							&& line[2].equals("com.example:project-b")
							&& line[3]
							.equals("None")));
			Assert.assertTrue(lines.stream()
					.anyMatch(line -> line[0].equals("com.example:project-b")
							&& line[1].equals("0")
							&& line[2].equals("None")
							&& line[3]
							.equals("org.third.party:library-c:2.0.4 (org.third.party:library-d:3.5.1)")));
		}
	}

	@Test
	public void testWriteDependenciesIOException() {
		Writer csvWriter = new StandardCsvWriter(RESOURCES + "output");
		File output = new File(RESOURCES + "output");
		output.delete();
		csvWriter.writeDependencies();
		Assert.assertEquals(
				"Exception occurred while writing dependency summary: src/test/resources/output/dependencies.csv (No such file or directory)",
				loggerRule.getMessages().get(0));
	}

	@Test
	public void testWriteVulnerabilitiesIOException() {
		Writer csvWriter = new StandardCsvWriter(RESOURCES + "output");
		File output = new File(RESOURCES + "output");
		output.delete();
		csvWriter.writeVulnerabilities();
		Assert.assertEquals(
				"Exception occurred while writing vulnerability summary: src/test/resources/output/vulnerabilities.csv (No such file or directory)",
				loggerRule.getMessages().get(0));
	}

	@Test
	public void testWriteTiersIOException() {
		Writer csvWriter = new StandardCsvWriter(RESOURCES + "output");
		File output = new File(RESOURCES + "output");
		output.delete();
		csvWriter.writeTiers();
		Assert.assertEquals(
				"Exception occurred while writing tier summary: src/test/resources/output/tiers.csv (No such file or directory)",
				loggerRule.getMessages().get(0));
	}
}
