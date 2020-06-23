const Doughnut = require('../libNode/doughnut').Doughnut;

let encodedDoughnut = new Uint8Array([
  // version and domain count
  0,0,3,
  // issuer
  236, 207, 36, 97, 218, 31, 28, 84, 72, 194, 96, 236, 127, 234, 137, 12,
  116, 55, 26, 227, 74, 221, 237, 217, 162, 70, 57, 10, 69, 139, 40, 59,
  // holder
  27, 137, 65, 29, 182, 25, 157, 61, 226, 13, 230, 14, 111, 6, 25, 186,
  227, 117, 177, 244, 172, 147, 40, 119, 209, 78, 13, 109, 236, 119, 205, 202,
  177,104,222,58,57,48,0,0,68,111,109,97,105,110,32,49,0,0,0,0,0,0,0,0,10,0,68,111,109,97,105,110,32,50,0,0,0,0,0,0,0,0,6,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,84,203,200,159,230,155,14,216,67,60,66,58,21,23,31,107,114,43,153,99,129,245,244,100,206,189,32,127,241,251,248,7,141,213,229,157,80,180,28,19,89,254,146,69,91,74,91,136,165,32,33,36,207,243,126,107,39,209,157,134,250,249,213,129
]);

describe("wasm doughnut", () => {
  test("it decodes and verifies", () => {
    let d = Doughnut.decode(encodedDoughnut);

    const holder = new Uint8Array([
      27, 137,  65,  29, 182,  25, 157,  61,
      226,  13, 230,  14, 111,   6,  25, 186,
      227, 117, 177, 244, 172, 147,  40, 119,
      209,  78,  13, 109, 236, 119, 205, 202
    ]);
    const issuer = new Uint8Array([
      236, 207, 36, 97, 218, 31, 28, 84, 72, 194, 96, 236, 127, 234, 137, 12,
      116, 55, 26, 227, 74, 221, 237, 217, 162, 70, 57, 10, 69, 139, 40, 59,
    ]);

    // Fields are correct
    expect(d.holder()).toEqual(holder);
    expect(d.issuer()).toEqual(issuer);
    expect(d.expiry()).toEqual(987654321);
    expect(d.notBefore()).toEqual(12345);
    expect(d.signatureVersion()).toEqual(0);
    expect(d.payloadVersion()).toEqual(0);

    // encodes the same
    expect(d.encode()).toEqual(encodedDoughnut);

    // verification ok
    expect(d.verify(holder, 12346)).toBeTruthy();
    // fail: expired
    expect(d.verify(holder, 987654322)).toBeFalsy();
    // fail: premature
    expect(d.verify(holder, 12344)).toBeFalsy();
    // fail: not the holder
    expect(d.verify(issuer, 12346)).toBeFalsy();
  });
});
