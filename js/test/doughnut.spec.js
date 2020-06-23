const Doughnut = require('../libNode/doughnut').Doughnut;

let encodedDoughnut = new Uint8Array([
  // version and domain count
  0, 0, 3,
  // issuer
  130, 69, 242, 131, 35, 253, 206, 156, 200, 34, 8, 238, 230, 74, 141, 60,
  162, 194, 114, 237, 159, 80, 92, 249, 40, 79, 32, 32, 38, 100, 164, 83,
  // holder
  21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
  21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
  // expiry
  196, 94, 16, 0, 75, 32, 0, 0,
  115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 1, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69, 108, 115, 101, 0, 0, 0, 1, 0, 0, 0, 220, 3, 169, 213, 97, 182, 23, 159, 37, 62, 148, 253, 195, 137, 124, 96, 62, 176, 169, 181, 74, 254, 232, 53, 58, 29, 133, 91, 187, 70, 214, 12, 59, 116, 120, 31, 192, 179, 26, 239, 203, 21, 120, 204, 156, 94, 7, 13, 191, 169, 188, 99, 242, 24, 122, 208, 44, 23, 164, 17, 14, 179, 12, 136
]);

describe("wasm doughnut", () => {
  test("it decodes and verifies", () => {
    let d = Doughnut.decode(encodedDoughnut);

    const holder = new Uint8Array([
      21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
      21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    ]);
    const issuer = new Uint8Array([
      130, 69, 242, 131, 35, 253, 206, 156, 200, 34, 8, 238, 230, 74, 141, 60,
      162, 194, 114, 237, 159, 80, 92, 249, 40, 79, 32, 32, 38, 100, 164, 83,
    ]);

    // Fields are correct
    expect(d.holder()).toEqual(holder);
    expect(d.issuer()).toEqual(issuer);
    expect(d.expiry()).toEqual(1072836);
    expect(d.notBefore()).toEqual(8267);
    expect(d.signatureVersion()).toEqual(0);
    expect(d.payloadVersion()).toEqual(0);

    // encodes the same
    expect(d.encode()).toEqual(encodedDoughnut);

    // verification ok
    expect(d.verify(holder, 12346)).toBeTruthy();
    // fail: expired
    expect(d.verify(holder, 987654322)).toBeFalsy();
    // fail: premature
    expect(d.verify(holder, 8266)).toBeFalsy();
    // fail: not the holder
    expect(d.verify(issuer, 12346)).toBeFalsy();
  });
});
