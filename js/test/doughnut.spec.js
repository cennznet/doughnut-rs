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
  27, 137,  65,  29, 182,  25, 157,  61,
  226,  13, 230,  14, 111,   6,  25, 186,
  227, 117, 177, 244, 172, 147,  40, 119,
  209,  78,  13, 109, 236, 119, 205, 202
];

const issuerBytesStub = [
  236, 207, 36, 97, 218, 31, 28, 84, 72, 194, 96, 236, 127, 234, 137, 12,
  116, 55, 26, 227, 74, 221, 237, 217, 162, 70, 57, 10, 69, 139, 40, 59,
];

const signatureBytesStub = [
  92, 204, 2, 72, 98, 182, 164, 188, 247, 27, 107, 126, 155, 164, 93, 20, 249, 252, 49, 11, 64, 87, 150, 233, 183, 246, 164, 178, 184, 80, 227, 83, 153, 135, 159, 188, 243, 163, 162, 114, 234, 15, 87, 134, 239, 197, 116, 249, 53, 112, 94, 112, 28, 220, 160, 248, 154, 78, 196, 169, 242, 60, 57, 135
];

const expiryStub = 987654321;

const notBeforeStub = 12345;

const encodedDoughnut = new Uint8Array(composeDoughnutBytes({
  holder: holderBytesStub,
  issuer: issuerBytesStub,
  signature: signatureBytesStub,
}));

describe("wasm doughnut", () => {
  test("functions work within decoded instance", () => {
    let d = Doughnut.decode(encodedDoughnut);

    const holder = new Uint8Array(holderBytesStub);
    const issuer = new Uint8Array(issuerBytesStub);
    const signature = new Uint8Array(signatureBytesStub);

    // Fields are correct
    expect(d.holder()).toEqual(holder);
    expect(d.issuer()).toEqual(issuer);
    expect(d.expiry()).toEqual(expiryStub);
    expect(d.notBefore()).toEqual(notBeforeStub);
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

  describe('Class instance', () => {
    test('functions work within Class instance', () => {
      const d = new Doughnut(issuerBytesStub, holderBytesStub, expiryStub, notBeforeStub);

      expect(d.holder()).toEqual(new Uint8Array(holderBytesStub));
      expect(d.issuer()).toEqual(new Uint8Array(issuerBytesStub));
      expect(d.expiry()).toEqual(expiryStub);
      expect(d.notBefore()).toEqual(notBeforeStub);
      expect(d.signatureVersion()).toEqual(0);
      expect(d.payloadVersion()).toEqual(0);
      expect(d.signature()).toEqual(new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      ]));
    });

    test.skip('sign sr25519 works', () => {
      const d = new Doughnut(issuerBytesStub, holderBytesStub, expiryStub, notBeforeStub);

      expect(d.signature()).toEqual(new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      ]));

      expect(d.signatureVersion()).toEqual(0);

      const sr25519SecretKey = new Uint8Array([
        72, 209, 112, 119, 208, 139, 58, 175, 151, 146, 127, 171, 136, 243, 122, 129, 35, 249, 98, 82, 112, 140, 212, 194, 194, 122, 80, 246, 211, 59, 202, 93, 197, 191, 152, 89, 209, 151, 153, 138, 218, 106, 91, 163, 187, 167, 119, 86, 106, 95, 106, 199, 173, 16, 249, 213, 14, 119, 172, 209, 18, 207, 124, 115
      ]);

      const expectedSignature = new Uint8Array([
      ]);

      const signature = d.sign_sr25519(sr25519SecretKey);

      expect(signature).toEqual(expectedSignature);
    });

    test('sign ed25519 works', () => {
      const d = new Doughnut(issuerBytesStub, holderBytesStub, expiryStub, notBeforeStub);

      expect(d.signature()).toEqual(new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      ]));

      expect(d.signatureVersion()).toEqual(0);

      const ed25519SecretKey = new Uint8Array([
        173, 129, 101, 216, 108, 187, 187, 148, 73, 100, 156, 26, 254, 229, 188, 52, 255, 108, 237, 125, 25, 93, 183, 68, 240, 130, 92, 38, 117, 177, 227, 228
      ]);

      const expectedSignature = new Uint8Array([
        94, 203, 191, 183, 108, 99, 144, 101, 65, 181, 159,
        130, 23, 34, 205, 123, 74, 56, 186, 120, 61, 200,
        170, 131, 167, 47, 102, 240, 87, 234, 54, 181, 121,
        133, 233, 99, 158, 79, 202, 116, 222, 155, 14, 47,
        66, 4, 107, 164, 49, 227, 166, 68, 50, 136, 132,
        41, 215, 169, 69, 43, 235, 105, 96, 9
      ]);

      console.log(d.sign_ed25519(ed25519SecretKey));

      const signature = d.sign_ed25519(ed25519SecretKey);
      expect(signature).toEqual(expectedSignature);
    });
  });
});
