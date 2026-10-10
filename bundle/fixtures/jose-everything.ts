import * as jose from "jose"
// Everything: the whole public API, as `import *` with dynamic use would retain.
;(globalThis as any).jose = jose
