const { stringToU8a } =  require('@polkadot/util');
const { schnorrkelKeypairFromSeed, naclKeypairFromSeed } = require('@polkadot/util-crypto');
const { waitReady } = require('@polkadot/wasm-crypto');
const Doughnut = require('../lib/doughnut').Doughnut;

let payload = [
  64, 24, 64, 22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62,
  185, 76, 45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67,
  105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138,
  38, 93, 144, 45, 224, 70, 206, 246, 116, 196, 94, 16, 0, 115, 111, 109, 101, 116, 104, 105,
  110, 103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69,
  108, 115, 101, 0, 0, 0, 128, 0, 0, 0, 8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176,
  31, 104, 162, 235, 78, 157, 166, 8, 137, 191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37,
  13, 218, 44, 244, 54, 137, 179, 56, 110, 152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24,
  240, 248, 244, 13, 51, 235, 3, 21, 63, 79, 192, 137, 6,
];

const issuer = new Uint8Array(32);
const holder = new Uint8Array(32);
const expiry = 100;
const not_before = 1;

const signature_version_sr25519 = 0;
const signature_version_ed25519 = 1;

const seed = stringToU8a('12345678901234567890123456789012');

const create_ed25519_keypair = () => {
  return naclKeypairFromSeed(seed);
};

const create_sr25519_keypair = () => {
  return schnorrkelKeypairFromSeed(seed);
};

const create_doughnut = (issuer) => {
  return Doughnut
    .new(issuer, holder, expiry, not_before)
    .add_payload_version(1)
    .add_domain('cennznet', [1, 2, 3])
    .add_domain('centrapay', [4, 5, 6]);
};

describe("wasm doughnut", () => {
  test("it should create doughnut with valid params", () => {
    let d = create_doughnut(issuer);

    expect(d.issuer()).toEqual(issuer);
    expect(d.holder()).toEqual(holder);
    expect(d.expiry()).toEqual(expiry);
    expect(d.not_before()).toEqual(not_before);
    expect(d.signature_version()).toEqual(signature_version_sr25519);
    expect(d.payload_version()).toEqual(1);
    expect(d.domain('cennznet')).toEqual(Uint8Array.from([1, 2, 3]));
    expect(d.domain('centrapay')).toEqual(Uint8Array.from([4, 5, 6]));
  });

  test("it should create doughnut from payload", () => {
    const d = Doughnut.decode(payload);

    expect(d.expiry()).toEqual(555555);
    expect(d.signature_version()).toEqual(3);
    expect(d.not_before()).toEqual(0);
    expect(d.payload_version()).toEqual(2);
    expect(d.encode().toString()).toEqual(payload.toString());
  });

  test("it should validate the doughnut with given issuer and time", () => {
    const d = create_doughnut(issuer);

    expect(d.validate(issuer, not_before - 1)).toEqual(false);
    expect(d.validate(issuer, not_before + 1)).toEqual(true);
    expect(d.validate(issuer, expiry + 1)).toEqual(false);
    expect(d.validate(issuer, expiry)).toEqual(false);
  });

  test("it should sign the doughnut with ed25519 signer", () => {
    const { publicKey, secretKey } = create_ed25519_keypair();
    const d = create_doughnut(publicKey).add_signature_version(1).sign(secretKey);

    expect(d.verify()).toEqual(true);
  });

  test("it should sign the doughnut with sr25519 signer", () => {
    // const { publicKey, secretKey } = create_sr25519_keypair();
    // const d = create_doughnut(publicKey);

    // d.sign(secretKey);
    // expect(d.verify()).toEqual(true);
  });
});
