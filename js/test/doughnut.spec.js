const Doughnut = require('../libNode/doughnut').Doughnut;

/**
 * Extract particular slices into params as needed 
 */
const composeDoughnutBytes = ({ holder, issuer, signature }) => ([
  // version and domain count
  0,0,3,
  // issuer
  236, 207, 36, 97, 218, 31, 28, 84, 72, 194, 96, 236, 127, 234, 137, 12,
  116, 55, 26, 227, 74, 221, 237, 217, 162, 70, 57, 10, 69, 139, 40, 59,
  // holder
  27, 137, 65, 29, 182, 25, 157, 61, 226, 13, 230, 14, 111, 6, 25, 186,
  227, 117, 177, 244, 172, 147, 40, 119, 209, 78, 13, 109, 236, 119, 205, 202,
  177,104,222,58,57,48,0,0,68,111,109,97,105,110,32,49,0,0,0,0,0,0,0,0,10,0,68,111,109,97,105,110,32,50,0,0,0,0,0,0,0,0,6,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,84,203,200,159,230,155,14,216,67,60,66,58,21,23,31,107,114,43,153,99,129,245,244,100,206,189,32,127,241,251,248,7,141,213,229,157,80,180,28,19,89,254,146,69,91,74,91,136,165,32,33,36,207,243,126,107,39,209,157,134,250,249,213,129,
  0, 0, 3,
  ...issuer,
  ...holder,
  // expiry
  177, 104, 222, 58, 57, 48, 0, 0,
  68, 111, 109, 97, 105, 110, 32, 49, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 68, 111, 109, 97, 105, 110, 32, 50, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  ...signature
]);

const holderBytesStub = [
  27, 137, 65, 29, 182, 25, 157, 61, 226, 13, 230, 14, 111, 6, 25, 186, 227, 117, 177, 244, 172, 147, 40, 119, 209, 78, 13, 109, 236, 119, 205, 202,
];

const issuerBytesStub = [
  212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
  76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

const signatureBytesStub = [
  92, 204, 2, 72, 98, 182, 164, 188, 247, 27, 107, 126, 155, 164, 93, 20, 249, 252, 49, 11, 64, 87, 150, 233, 183, 246, 164, 178, 184, 80, 227, 83, 153, 135, 159, 188, 243, 163, 162, 114, 234, 15, 87, 134, 239, 197, 116, 249, 53, 112, 94, 112, 28, 220, 160, 248, 154, 78, 196, 169, 242, 60, 57, 135
];

const encodedDoughnut = new Uint8Array(composeDoughnutBytes({
  holder: holderBytesStub,
  issuer: issuerBytesStub, 
  signature: signatureBytesStub, 
}));

describe("wasm doughnut", () => {
  test("functions work within decoded instance", () => {
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

    const signature = new Uint8Array([
      92, 204, 2, 72, 98, 182, 164, 188, 247, 27, 107, 126, 155, 164, 93, 20, 249, 252, 49, 11, 64, 87, 150, 233, 183, 246, 164, 178, 184, 80, 227, 83, 153, 135, 159, 188, 243, 163, 162, 114, 234, 15, 87, 134, 239, 197, 116, 249, 53, 112, 94, 112, 28, 220, 160, 248, 154, 78, 196, 169, 242, 60, 57, 135
    ]);

    // Fields are correct
    expect(d.holder()).toEqual(holder);
    expect(d.issuer()).toEqual(issuer);
    expect(d.expiry()).toEqual(987654321);
    expect(d.notBefore()).toEqual(12345);
    expect(d.signatureVersion()).toEqual(0);
    expect(d.signature()).toEqual(signature);
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

  test('functions work within Class instance', () => {
    const d = new Doughnut(issuerBytesStub, holderBytesStub, 987654321, 123);
    // expect(d).toEqual();

    const secretKey = new Uint8Array([]);
    const signature = d.sign_sr25519(secretKey);
    // expect(signature).toEqual(signatureBytesStub);
  });
});
