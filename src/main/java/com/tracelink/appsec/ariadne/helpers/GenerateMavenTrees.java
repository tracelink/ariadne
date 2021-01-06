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
package com.tracelink.appsec.ariadne.helpers;

import com.tracelink.appsec.ariadne.Ariadne;

/**
 * Generates Maven dependency trees for all projects that are contained within a provided
 * directory. These dependencies trees can then be used as an input to {@link Ariadne} in order to
 * construct a dependency graph of multiple Maven projects.
 *
 * @author mcool
 */
public class GenerateMavenTrees {

	/**
	 * Main method to generate Maven dependency trees for a group of projects.
	 *
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		// Parse command line arguments
		GenerateMavenTreesCLI cli = new GenerateMavenTreesCLI();
		boolean success = cli.parseArgs(args);
		if (!success) {
			return;
		}
		// Configure generator with command line arguments
		MavenTreeGenerator generator = new MavenTreeGenerator(cli.getOutputDir(), cli.getMaxDepth(),
				cli.getDefaultOption(), cli.getSpecialOptions());
		// Build dependency trees
		generator.buildTrees(cli.getProjectsDir(), 0);
		generator.identifyParents(cli.getProjectsDir(), 0);
	}
}
