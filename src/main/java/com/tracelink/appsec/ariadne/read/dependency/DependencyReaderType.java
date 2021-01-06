/*
Copyright 2019 TraceLink, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.tracelink.appsec.ariadne.read.dependency;

/**
 * Enum defining the valid dependency reader types. Each type corresponds to a single {@link
 * DependencyReader} implementation.
 *
 * @author mcool
 */
public enum DependencyReaderType {
	MAVEN_TREE("mvn-tree"), POM_EXPLORER("pom-explorer");

	private final String name;

	DependencyReaderType(String name) {
		this.name = name;
	}

	/**
	 * Gets the {@link DependencyReaderType} with the given name, if it exists.
	 *
	 * @param name name of the dependency reader type to get
	 * @return dependency reader type with the given name
	 * @throws IllegalArgumentException if no such dependency reader type exists
	 */
	public static DependencyReaderType getTypeForName(String name) {
		for (DependencyReaderType type : DependencyReaderType.values()) {
			if (type.name.equals(name)) {
				return type;
			}
		}
		throw new IllegalArgumentException("Unknown dependency reader type - " + name);
	}
}
