const native = await import("../native/index.node");

if (native.default.nativeReady() !== true) {
  throw new Error("nativeReady() did not return true");
}

console.log("napi-rs native addon loaded");
