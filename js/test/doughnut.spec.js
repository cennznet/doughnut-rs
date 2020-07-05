const Doughnut = require('../libNode/doughnut').Doughnut;
// const testingPairs = require('@polkadot/keyring/testingPairs');
// const keyring = testingPairs({ type: 'sr25519' });
const { waitReady } = require('@polkadot/wasm-crypto');
const { Keyring } = require('@polkadot/keyring');
const { hexToU8a } = require('@polkadot/util');
/**
 * Extract particular slices into params as needed
 */
const composeDoughnutBytes = ({ versions, issuer, holder, signature }) => [
  // payload version + signature version
  ...versions,
  3,
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
  publicKey: [ 212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125 ],
  secretKey: [ 152, 49, 157, 79, 248, 169, 80, 140, 75, 176, 207, 11, 90, 120, 215, 96, 160, 178, 8, 44, 2, 119, 94, 110, 130, 55, 8, 22, 254, 223, 255, 72, 146, 90, 34, 93, 151, 170, 0, 104, 45, 106, 89, 185, 91, 24, 120, 12, 16, 215, 3, 35, 54, 232, 143, 52, 66, 180, 35, 97, 244, 166, 96, 17, ],
};

const signatureBytes = [
  92, 204, 2, 72, 98, 182, 164, 188, 247, 27, 107, 126, 155, 164, 93, 20, 249, 252, 49, 11, 64, 87, 150, 233, 183, 246, 164, 178, 184, 80, 227, 83, 153, 135, 159, 188, 243, 163, 162, 114, 234, 15, 87, 134, 239, 197, 116, 249, 53, 112, 94, 112, 28, 220, 160, 248, 154, 78, 196, 169, 242, 60, 57, 135,
];

const expiry = 987654321;

const notBefore = 12345;

const defaultSignatureBeforeSigning = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

describe('wasm doughnut', () => {
  beforeEach(async () => {
    await waitReady();
  });

  describe('Decoded instance', () => {
    test('sr25519 encoding and decoding work', () => {
      const sr25519Bytes = composeDoughnutBytes({
        versions: [0, 0],
        holder: holderBytes,
        issuer: sr25519Keypair.publicKey,
        signature: signatureBytes,
      });

      const sr25519Doughnut = new Uint8Array(sr25519Bytes);

      const d = Doughnut.decode(sr25519Doughnut);

      const holder = new Uint8Array(holderBytes);
      const issuer = new Uint8Array(sr25519Keypair.publicKey);
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
      expect(d.encode()).toEqual(sr25519Doughnut);

      // verification ok
      // expect(d.verify(holder, holder)).toBeTruthy();
      // fail: expired
      expect(d.verify(holder, 987654322)).toBeFalsy();
      // fail: premature
      expect(d.verify(holder, 12344)).toBeFalsy();
      // fail: not the holder
      expect(d.verify(issuer, 12346)).toBeFalsy();
    });

    test('ed25519 encoding and decoding work', () => {
      const ed25519Bytes = composeDoughnutBytes({
        versions: [0, 8],
        holder: holderBytes,
        issuer: ed25519Keypair.publicKey,
        signature: signatureBytes,
      });

      const ed25519Doughnut = new Uint8Array(ed25519Bytes);

      const d = Doughnut.decode(ed25519Doughnut);

      const holder = new Uint8Array(holderBytes);
      const issuer = new Uint8Array(ed25519Keypair.publicKey);
      const signature = new Uint8Array(signatureBytes);

      // Fields are correct
      expect(d.holder()).toEqual(holder);
      expect(d.issuer()).toEqual(issuer);
      expect(d.expiry()).toEqual(expiry);
      expect(d.notBefore()).toEqual(notBefore);
      expect(d.signatureVersion()).toEqual(1);
      expect(d.signature()).toEqual(signature);
      expect(d.payloadVersion()).toEqual(0);

      // encodes the same
      expect(d.encode()).toEqual(ed25519Doughnut);

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

      const keyring = new Keyring({ type: 'sr25519' });
      const alice = keyring.addFromUri('//Alice', { name: 'Alice' });

      // publicKey: hexToU8a('0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d'),
      //   secretKey: hexToU8a('0x98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011'),

      // keyring.alice.publicKey Uint8Array(32)[
      //   212, 53, 147, 199, 21, 253, 211, 28,
      //   97, 20, 26, 189, 4, 169, 159, 214,
      //   130, 44, 133, 88, 133, 76, 205, 227,
      //   154, 86, 132, 231, 165, 109, 162, 125
      // ]

      // hexToU8a secretkey Uint8Array(64)[
      //   152, 49, 157, 79, 248, 169, 80, 140, 75, 176, 207,
      //   11, 90, 120, 215, 96, 160, 178, 8, 44, 2, 119,
      //   94, 110, 130, 55, 8, 22, 254, 223, 255, 72, 146,
      //   90, 34, 93, 151, 170, 0, 104, 45, 106, 89, 185,
      //   91, 24, 120, 12, 16, 215, 3, 35, 54, 232, 143,
      //   52, 66, 180, 35, 97, 244, 166, 96, 17
      // ]

      // console.log('keyring.alice.publicKey', alice.publicKey);
      // console.log('hexToU8a publickey', hexToU8a('0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d'));
      // console.log('hexToU8a secretkey', hexToU8a('0x98319d4ff8a9508c4bb0cf0b5a78d760a0b2082c02775e6e82370816fedfff48925a225d97aa00682d6a59b95b18780c10d7032336e88f3442b42361f4a66011'));
      // console.log('keyring', alice);

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
