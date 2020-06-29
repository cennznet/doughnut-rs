const Doughnut = require('../libNode/doughnut').Doughnut;

/**
 * Extract particular slices into params as needed
 */
const composeDoughnutBytes = ({ issuer, holder, signature }) => [
  // version and domain count
  0, 0, 3,
  ...issuer,
  ...holder,
  177, 104, 222, 58, 57, 48, 0, 0, 68, 111, 109, 97, 105, 110, 32, 49, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 68, 111, 109, 97, 105, 110, 32, 50, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  ...signature,
];

const holderBytes = [
  27, 137, 65, 29, 182, 25, 157, 61, 226, 13, 230, 14, 111, 6, 25, 186, 227, 117, 177, 244, 172, 147, 40, 119, 209, 78, 13, 109, 236, 119, 205, 202,
];

const ed25519Keypair = {
  publicKey: [
    150, 22, 44, 205, 2, 222, 76, 191, 190, 171, 49, 135, 116, 73, 75, 214, 129, 172, 123, 53, 115, 170, 24, 156, 51, 98, 166, 110, 214, 167, 219, 123,
  ],
  secretKey: [
    254, 24, 199, 193, 126, 65, 43, 25, 235, 81, 36, 59, 82, 249, 196, 85, 121, 180, 34, 77, 21, 231, 35, 178, 241, 63, 167, 51, 65, 29, 41, 137,
  ],
};

const sr25519Keypair = {
  publicKey: [
    218, 34, 94, 244, 140, 155, 254, 140, 97, 227, 158, 4, 69, 75, 198, 210, 38, 69, 50, 58, 196, 218, 12, 145, 58, 42, 154, 225, 227, 134, 17, 115
  ],
  secretKey: [
    128, 44, 191, 250, 79, 102, 78, 92, 203, 152, 149, 213, 121, 67, 51, 144, 225, 199, 36, 71, 6, 250, 239, 137, 140, 141, 39, 60, 98, 69, 232, 86, 75, 146, 151, 132, 120, 221, 240, 22, 36, 22, 64, 31, 154, 208, 27, 68, 236, 254, 55, 76, 74, 143, 57, 211, 13, 53, 128, 124, 95, 251, 4, 189
  ],
};

const signatureBytes = [
  92, 204, 2, 72, 98, 182, 164, 188, 247, 27, 107, 126, 155, 164, 93, 20, 249, 252, 49, 11, 64, 87, 150, 233, 183, 246, 164, 178, 184, 80, 227, 83, 153, 135, 159, 188, 243, 163, 162, 114, 234, 15, 87, 134, 239, 197, 116, 249, 53, 112, 94, 112, 28, 220, 160, 248, 154, 78, 196, 169, 242, 60, 57, 135,
];

const expiry = 987654321;

const notBefore = 12345;

const defaultSignatureBeforeSigning = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]

const encodedDoughnut = new Uint8Array(
  composeDoughnutBytes({
    holder: holderBytes,
    issuer: ed25519Keypair.publicKey,
    signature: signatureBytes,
  })
);

describe('wasm doughnut', () => {
  describe('Decoded instance', () => {
    test('getters work', () => {
      let d = Doughnut.decode(encodedDoughnut);

      const holder = new Uint8Array(holderBytes);
      const issuer = new Uint8Array(ed25519Keypair.publicKey);
      const signature = new Uint8Array(signatureBytes);

      // Fields are correct
      expect(d.holder()).toEqual(holder);
      expect(d.issuer()).toEqual(issuer);
      expect(d.expiry()).toEqual(expiry);
      expect(d.notBefore()).toEqual(notBefore);
      expect(d.signatureVersion()).toEqual(0);
      expect(d.signature()).toEqual(signature);
      expect(d.payloadVersion()).toEqual(0);

      // encodes the same
      expect(d.encode()).toEqual(encodedDoughnut);

      // verification ok
      // expect(d.verify(holder, holder)).toBeTruthy();
      // fail: expired
      expect(d.verify(holder, 987654322)).toBeFalsy();
      // fail: premature
      expect(d.verify(holder, 12344)).toBeFalsy();
      // fail: not the holder
      expect(d.verify(issuer, 12346)).toBeFalsy();
    });
  });

  describe('Class instance', () => {
    test('getters work', () => {
      const d = new Doughnut(
        ed25519Keypair.publicKey,
        holderBytes,
        expiry,
        notBefore
      );

      expect(d.holder()).toEqual(new Uint8Array(holderBytes));
      expect(d.issuer()).toEqual(new Uint8Array(ed25519Keypair.publicKey));
      expect(d.expiry()).toEqual(expiry);
      expect(d.notBefore()).toEqual(notBefore);
      expect(d.signatureVersion()).toEqual(0);
      expect(d.payloadVersion()).toEqual(0);
      expect(d.signature()).toEqual(
        new Uint8Array([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
      );
    });

    test('sr25519 signing', () => {
      const d = new Doughnut(
        sr25519Keypair.publicKey,
        holderBytes,
        expiry,
        notBefore
      );

      expect(d.signature()).toEqual(
        new Uint8Array(defaultSignatureBeforeSigning)
      );

      expect(d.signatureVersion()).toEqual(0);

      const signedSignature = new Uint8Array([]);

      d.signSr25519(sr25519Keypair.secretKey);

      expect(d.signature()).toEqual(signedSignature);
    });

    test('ed25519 signing', () => {
      const d = new Doughnut(
        ed25519Keypair.publicKey,
        holderBytes,
        expiry,
        notBefore
      );

      expect(d.signature()).toEqual(
        new Uint8Array(defaultSignatureBeforeSigning)
      );

      // To be fixed
      expect(d.signatureVersion()).toEqual(0);

      const signedSignature = new Uint8Array([
        90, 143, 31, 88, 7, 153, 88, 176, 209, 39, 71, 65, 16, 116, 95, 143, 125, 99, 21, 60, 109, 250, 196, 2, 107, 14, 164, 101, 110, 235, 151, 76, 136, 156, 88, 112, 164, 29, 68, 185, 16, 246, 206, 52, 94, 190, 226, 158, 201, 110, 81, 253, 184, 118, 189, 149, 226, 203, 63, 146, 23, 217, 177, 9,
      ]);

      d.signEd25519(ed25519Keypair.secretKey);

      expect(d.signature()).toEqual(signedSignature);
    });
  });
});
