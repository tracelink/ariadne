package com.tracelink.appsec.ariadne.model;

import org.junit.Assert;
import org.junit.Test;

public class TestInternalArtifact {
    @Test(expected = UnsupportedOperationException.class)
    public void testAssignTiers() {
        new InternalArtifact("com.example:project-a:1.0").assignTiers();
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testAddFindings() {
        new InternalArtifact("com.example:project-a:1.0").addFindings(1);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetFindings() {
        new InternalArtifact("com.example:project-a:1.0").getFindings();
    }

    @Test
    public void addParentNoMatchingVersion() {
        InternalArtifact artifact = new InternalArtifact("com.example:project-a:1.0");
        int origConnections = artifact.getConnections();
        artifact.addParent("2.0", new InternalArtifact("com.example:project-b:1.0"));
        Assert.assertEquals(origConnections, artifact.getConnections());
    }

    @Test
    public void addChildNoMatchingVersion() {
        InternalArtifact artifact = new InternalArtifact("com.example:project-a:1.0");
        int origConnections = artifact.getVersions().size();
        artifact.addChild("2.0", new InternalArtifact("com.example:project-b:1.0"));
        Assert.assertEquals(origConnections, artifact.getVersions().size());
    }
}
