import { createRequire } from "node:module";

const native = createRequire(import.meta.url)("../native/index.node");

if (native.nativeReady() !== true) {
  throw new Error("nativeReady() did not return true");
}

console.log("napi-rs native addon loaded");
