package com.tracelink.appsec.ariadne.read.dependency;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class PomExplorerReaderTest {

	private static final String RESOURCES = "src/test/resources/";

	@Test
	public void testReadDependencies() throws IOException {
		DependencyReader reader = new PomExplorerReader(
				RESOURCES + "dependency/pom-explorer.csv");
		List<Map.Entry<String, String>> dependencies = reader.readDependencies();

		Assert.assertEquals(5, dependencies.size());
		Assert.assertTrue(dependencies.stream().anyMatch(d ->
				d.getKey().equals("com.example:project-a:1.0")
						&& d.getValue().equals("com.example:project-b:2.0")
		));
		Assert.assertTrue(dependencies.stream().anyMatch(d ->
				d.getKey().equals("com.example:project-a:1.0")
						&& d.getValue().equals("com.example:project-c:3.0")
		));
		Assert.assertTrue(dependencies.stream().anyMatch(d ->
				d.getKey().equals("com.example:project-a:1.0")
						&& d.getValue().equals("com.example:project-d:4.0")
		));
		Assert.assertTrue(dependencies.stream().anyMatch(d ->
				d.getKey().equals("com.example:project-a:1.0")
						&& d.getValue().equals("com.example:project-e:5.0")
		));
		Assert.assertTrue(dependencies.stream().anyMatch(d ->
				d.getKey().equals("com.example:project-c:3.0")
						&& d.getValue().equals("org.third.party:library-f:6.0")
		));
		Assert.assertFalse(dependencies.stream().anyMatch(d ->
				d.getKey().equals("from")
						&& d.getValue().equals("to")
		));
	}

	@Test(expected = FileNotFoundException.class)
	public void testPomExplorerReaderFileDoesNotExist() throws Exception {
		new PomExplorerReader(RESOURCES + "foo.txt");
	}

	@Test(expected = FileNotFoundException.class)
	public void testPomExplorerReaderInvalidDirectory() throws Exception {
		new PomExplorerReader(RESOURCES + "trees");
	}
}
