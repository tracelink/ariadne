package com.tracelink.appsec.ariadne.write;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Test;

public class TestStandardCsvWriter {
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
}
