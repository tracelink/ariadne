package com.tracelink.appsec.ariadne;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

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
    public void testAriadne() throws IOException {
        Ariadne.main(new String[]{
                "-d", "mvn-tree", "src/test/resources/dependency-tree.txt",
                "-v", "nexus-iq-vios", "src/test/resources/violations.csv",
                "-w", "csv", "src/test/resources/output/",
                "-i", "com.example"
        });

        try(BufferedReader fileReader = new BufferedReader(new FileReader("src/test/resources/output/tiers.csv"))){
	        List<String> lines = fileReader.lines().collect(Collectors.toList());
	        Assert.assertTrue(lines.stream().anyMatch(line ->
	                line.contains("com.example:project-a") && line.contains(",1,")));
	        Assert.assertTrue(lines.stream().anyMatch(line ->
	                line.contains("com.example:project-b") && line.contains(",0,")));
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
