export function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export const issuer = new Uint8Array([0x01, 0x02]);
export const otherIssuer = new Uint8Array([0x03, 0x04]);
export const requestDer = new Uint8Array([0x10, 0x11]);
export const certificate = new Uint8Array([0x20, 0x21]);
