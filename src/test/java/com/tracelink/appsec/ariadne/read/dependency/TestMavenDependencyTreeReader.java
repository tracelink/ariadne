package com.tracelink.appsec.ariadne.read.dependency;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class TestMavenDependencyTreeReader {

    @Test
    public void testReadDependenciesSimpleTree() throws IOException {
        DependencyReader reader = new MavenDependencyTreeReader("src/test/resources/simple-tree.txt");
        List<Map.Entry<String, String>> dependencies = reader.readDependencies();

        Assert.assertEquals(3, dependencies.size());
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
                        && d.getValue().equals("org.third.party:library-d:4.0")
        ));
    }

    @Test
    public void testReadDependenciesComplexTree() throws IOException {
        DependencyReader reader = new MavenDependencyTreeReader("src/test/resources/complex-tree.txt");
        List<Map.Entry<String, String>> dependencies = reader.readDependencies();

        Assert.assertEquals(7, dependencies.size());
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("com.example:project-a:1.0")
                        && d.getValue().equals("com.example:project-b:2.0")
        ));
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("com.example:project-b:2.0")
                        && d.getValue().equals("com.example:project-c:3.0")
        ));
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("com.example:project-c:3.0")
                        && d.getValue().equals("org.third.party:library-d:4.0")
        ));
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("com.example:project-b:2.0")
                        && d.getValue().equals("org.third.party:library-e:5.0")
        ));
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("com.example:project-a:1.0")
                        && d.getValue().equals("org.third.party:library-f:6.0")
        ));
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("com.example:project-a:1.0")
                        && d.getValue().equals("org.third.party:library-g:7.0")
        ));
        Assert.assertTrue(dependencies.stream().anyMatch(d ->
                d.getKey().equals("org.third.party:library-g:7.0")
                        && d.getValue().equals("org.third.party:library-h:8.0")
        ));
    }
}
