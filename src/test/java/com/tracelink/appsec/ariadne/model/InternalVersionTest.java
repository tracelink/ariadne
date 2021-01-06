package com.tracelink.appsec.ariadne.model;

import org.junit.Assert;
import org.junit.Test;

public class InternalVersionTest {

	@Test
	public void testCompareToSimpleVersion() {
		// Simple version numbers of same length
		InternalVersion v1 = new InternalVersion("10.0");
		InternalVersion v2 = new InternalVersion("0.1");
		Assert.assertTrue(v1.compareTo(v2) < 0);

		// Two versions with same number
		v1 = new InternalVersion("1.0");
		v2 = new InternalVersion("1.0");
		Assert.assertEquals(0, v1.compareTo(v2));

		// Version numbers of different length
		v2 = new InternalVersion("1.0.1");
		Assert.assertTrue(v1.compareTo(v2) > 0);

		v1 = new InternalVersion("1.0.2");
		v2 = new InternalVersion("1.0");
		Assert.assertTrue(v1.compareTo(v2) < 0);
	}

	@Test
	public void testCompareToMismatched() {
		// One has build one doesn't
		InternalVersion v1 = new InternalVersion("1.0-1");
		InternalVersion v2 = new InternalVersion("1.0");
		Assert.assertTrue(v1.compareTo(v2) < 0);

		v1 = new InternalVersion("1.10");
		v2 = new InternalVersion("1.10-5");
		Assert.assertTrue(v1.compareTo(v2) > 0);

		// One doesn't match the version regex
		v1 = new InternalVersion("foo");
		v2 = new InternalVersion("1.2");
		Assert.assertTrue(v1.compareTo(v2) > 0);

		v1 = new InternalVersion("1.2");
		v2 = new InternalVersion("foo");
		Assert.assertTrue(v1.compareTo(v2) < 0);

		// Both don't match the version regex
		v1 = new InternalVersion("bar");
		Assert.assertTrue(v1.compareTo(v2) > 0);
	}

	@Test
	public void testCompareToComplex() {
		// Equal versions
		InternalVersion v1 = new InternalVersion("1.0-1");
		InternalVersion v2 = new InternalVersion("1.0-1");
		Assert.assertEquals(0, v1.compareTo(v2));

		// First one is a SNAPSHOT
		v1 = new InternalVersion("1.0-SNAPSHOT");
		Assert.assertTrue(v1.compareTo(v2) < 0);

		// Second one is a SNAPSHOT
		v1 = new InternalVersion("1.0-7");
		v2 = new InternalVersion("1.0-SNAPSHOT");
		Assert.assertTrue(v1.compareTo(v2) > 0);

		// Neither is a SNAPSHOT
		v2 = new InternalVersion("1.0-12");
		Assert.assertTrue(v1.compareTo(v2) > 0);
	}
}
