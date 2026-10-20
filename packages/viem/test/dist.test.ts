// Checks of the built package in a plain node process.

import { describeBuiltAdapter } from "@w3tech.io/vrpc-test-support";

describeBuiltAdapter("@w3tech.io/vrpc-viem", new URL("../dist", import.meta.url));
