package com.tracelink.appsec.ariadne.analyze;

import com.tracelink.appsec.ariadne.model.Artifact;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class TestAnalyzer {
    private Analyzer analyzer;

    @Before
    public void init() {
        analyzer = new Analyzer(Collections.singletonList("com.example"));
    }

    @Test
    public void testAnalyzeDependencies() {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "com.example:project-b:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-b:1.0", "com.example:project-c:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-b:2.0", "org.third.party:library-d:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-d:1.0", "org.third.party:library-e:1.0"));
        analyzer.analyzeDependencies(dependencies);

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(5, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-a")
                        && a.getVersions().size() == 1));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-b")
                        && a.getVersions().size() == 2));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-c")
                        && a.getVersions().size() == 1));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-d:1.0")
                        && a.getVersions().size() == 1));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-e:1.0")
                        && a.getVersions().size() == 1));
    }

    @Test
    public void testAnalyzeVulnerabilities() {
        List<Map.Entry<String, Integer>> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-a:1.0", 1));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-b:1.0", 2));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-c:1.0", 3));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-c:2.0", 4));
        analyzer.analyzeVulnerabilities(vulnerabilities);

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(4, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-a:1.0")
                        && a.isVulnerable() && a.getFindings() == 1));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-b:1.0")
                        && a.isVulnerable() && a.getFindings() == 2));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-c:1.0")
                        && a.isVulnerable() && a.getFindings() == 3));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-c:2.0")
                        && a.isVulnerable() && a.getFindings() == 4));
    }

    @Test
    public void testAnalyzeTiersLoop() {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "com.example:project-b:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-b:1.0", "com.example:project-c:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-c:1.0", "com.example:project-a:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-c:1.0", "com.example:project-d:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-d:1.0", "org.third.party:library-e:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-f:1.0", "org.third.party:library-g:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-g:1.0", "org.third.party:library-h:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-h:1.0", "org.third.party:library-f:1.0"));


        List<Map.Entry<String, Integer>> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-e:1.0", 1));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-h:1.0", 1));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-i:1.0", 1));

        analyzer.analyzeDependencies(dependencies);
        analyzer.analyzeVulnerabilities(vulnerabilities);
        analyzer.analyzeTiers();

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(9, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-a")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-b")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-b")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-c")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-c")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-a")
                        && a.getInternalUpgrades().contains("com.example:project-d")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-d")
                        && a.getTier() == 0
                        && a.getExternalUpgrades().containsKey("org.third.party:library-e:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-e:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-f:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-g:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-h:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-i:1.0")));
    }

    @Test
    public void testAnalyzeTiersAboveLoop() {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "com.example:project-b:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-b:1.0", "com.example:project-c:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-c:1.0", "com.example:project-a:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-c:1.0", "com.example:project-d:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-i:1.0", "com.example:project-a:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-d:1.0", "org.third.party:library-e:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-f:1.0", "org.third.party:library-g:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-g:1.0", "org.third.party:library-h:1.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-h:1.0", "org.third.party:library-f:1.0"));


        List<Map.Entry<String, Integer>> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-e:1.0", 1));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-h:1.0", 1));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-i:1.0", 1));

        analyzer.analyzeDependencies(dependencies);
        analyzer.analyzeVulnerabilities(vulnerabilities);
        analyzer.analyzeTiers();

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(10, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-a")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-b")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-b")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-c")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-c")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-a")
                        && a.getInternalUpgrades().contains("com.example:project-d")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-d")
                        && a.getTier() == 0
                        && a.getExternalUpgrades().containsKey("org.third.party:library-e:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-e:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-f:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-g:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-h:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-i:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-i")
                        && a.getTier() == 2
                        && a.getInternalUpgrades().contains("com.example:project-a")));
    }

    @Test
    public void testAnalyzeTiersDeferTier() {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "com.example:project-b:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "org.third.party:library-c:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-b:1.0", "org.third.party:library-c:1.0"));

        List<Map.Entry<String, Integer>> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-c:1.0", 1));

        analyzer.analyzeDependencies(dependencies);
        analyzer.analyzeVulnerabilities(vulnerabilities);
        analyzer.analyzeTiers();

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(3, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-a")
                        && a.getTier() == 1
                        && a.getInternalUpgrades().contains("com.example:project-b")
                        && a.getExternalUpgrades().containsKey("org.third.party:library-c:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-b")
                        && a.getTier() == 0
                        && a.getExternalUpgrades().containsKey("org.third.party:library-c:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-c:1.0")));
    }

    @Test
    public void testAnalyzeTiersNotMostRecentVersion() {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "com.example:project-b:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:2.0", "com.example:project-d:1.0"));
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-b:1.0", "org.third.party:library-c:1.0"));

        List<Map.Entry<String, Integer>> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-c:1.0", 1));

        analyzer.analyzeDependencies(dependencies);
        analyzer.analyzeVulnerabilities(vulnerabilities);
        analyzer.analyzeTiers();

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(4, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-a")
                        && a.getTier() == -1
                        && a.getInternalUpgrades().isEmpty()
                        && a.getExternalUpgrades().isEmpty()));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-d")
                        && a.getTier() == -1
                        && a.getInternalUpgrades().isEmpty()
                        && a.getExternalUpgrades().isEmpty()));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-b")
                        && a.getTier() == 0
                        && a.getExternalUpgrades().containsKey("org.third.party:library-c:1.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-c:1.0")));
    }

    @Test
    public void testAnalyzeTiersTransitiveVulnerability() {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();
        dependencies.add(new AbstractMap.SimpleEntry<>("com.example:project-a:1.0", "org.third.party:library-b:2.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-b:2.0", "org.third.party:library-c:3.0"));
        dependencies
                .add(new AbstractMap.SimpleEntry<>("org.third.party:library-b:2.0", "org.third.party:library-d:4.0"));

        List<Map.Entry<String, Integer>> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-c:3.0", 1));
        vulnerabilities.add(new AbstractMap.SimpleEntry<>("org.third.party:library-d:4.0", 1));

        analyzer.analyzeDependencies(dependencies);
        analyzer.analyzeVulnerabilities(vulnerabilities);
        analyzer.analyzeTiers();

        Collection<Artifact> artifacts = analyzer.getArtifacts();
        Assert.assertEquals(4, artifacts.size());
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("com.example:project-a")
                        && a.getTier() == 0
                        && a.getExternalUpgrades().containsKey("org.third.party:library-b:2.0")
                        && a.getExternalUpgrades().get("org.third.party:library-b:2.0")
                        .contains("org.third.party:library-c:3.0")
                        && a.getExternalUpgrades().get("org.third.party:library-b:2.0")
                        .contains("org.third.party:library-d:4.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-b:2.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-c:3.0")));
        Assert.assertTrue(artifacts.stream().anyMatch(a ->
                a.getName().equals("org.third.party:library-d:4.0")));
    }
}
