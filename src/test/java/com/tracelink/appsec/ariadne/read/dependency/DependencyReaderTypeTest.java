package com.tracelink.appsec.ariadne.read.dependency;

import org.junit.Test;

public class DependencyReaderTypeTest {

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidDependencyReaderType() {
		DependencyReaderType.getTypeForName("invalid");
	}

}

