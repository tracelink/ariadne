package com.tracelink.appsec.ariadne.cli;

import com.tracelink.appsec.ariadne.read.dependency.PomExplorerReader;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;

public class TestAriadneCLI {
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
    public void testParseArgsPomExplorer() {
        AriadneCLI cli = new AriadneCLI();
        cli.parseArgs(new String[]{
                "-d", "pom-explorer", "src/test/resources/pom-explorer.csv",
                "-v", "nexus-iq-vios", "src/test/resources/violations.csv",
                "-w", "csv", "src/test/resources/output/",
                "-i", "com.example"
        });

        Assert.assertTrue(cli.getDependencyReader() instanceof PomExplorerReader);
    }

    @Test()
    public void testParseArgsBadType() {
        AriadneCLI cli = new AriadneCLI();
        cli.parseArgs(new String[]{
                "-d", "pom-explorer", "src/test/resources/pom-explorer.csv",
                "-v", "nexus-iq-vios", "src/test/resources/violations.csv",
                "-w", "foo", "src/test/resources/output/",
                "-i", "com.example"
        });
    }
}
