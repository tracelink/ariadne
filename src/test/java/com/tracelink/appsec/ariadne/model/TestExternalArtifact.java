package com.tracelink.appsec.ariadne.model;

import org.junit.Test;

import java.util.Collections;

public class TestExternalArtifact {
    @Test(expected=UnsupportedOperationException.class)
    public void testAddVersion() {
        new ExternalArtifact("org.third.party:library-a:1.0").addVersion("2.0");
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testGetInternalUpgrades() {
        new ExternalArtifact("org.third.party:library-a:1.0").getInternalUpgrades();
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testGetExternalUpgrades() {
        new ExternalArtifact("org.third.party:library-a:1.0").getExternalUpgrades();
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testFindCycles() {
        new ExternalArtifact("org.third.party:library-a:1.0").findCycles(Collections.emptyList());
    }
}
