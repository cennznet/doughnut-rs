const Doughnut = require('../lib/doughnut.js').DoughnutHandle;

let issuer = new Uint8Array(32);
let holder = new Uint8Array(32);
let expiry = 100;
let not_before = 1;

describe("wasm doughnut", () => {
  test("create doughnut should work", () => {
    let d = Doughnut
      .new(issuer, holder, expiry, not_before)
      .add_payload_version(1)
      .add_signature_version(2)
      .add_domain('cennznet', [1, 2, 3]);

    expect(d.issuer()).toEqual(issuer);
    expect(d.holder()).toEqual(holder);
    expect(d.expiry()).toEqual(expiry);
    expect(d.not_before()).toEqual(not_before);
    // expect(d.signature_version()).toEqual(2);
    // expect(d.payload_version()).toEqual(1);
    // expect(d.domain('cennznet')).toEqual([1, 2, 3]);
  });

  test("it should create doughnut from payload", () => {
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
    let d = Doughnut.decode(payload);

    expect(d.expiry()).toEqual(555555);
    expect(d.signature_version()).toEqual(3);
    expect(d.not_before()).toEqual(0);
    expect(d.encode().toString()).toEqual(payload.toString());
    expect(d.payload_version()).toEqual(2);
  });

  test("it should sign the doughnut with signer", () => {
  });

  test("it should verify the signature with correct doughnut", () => {

  });

  test("it should be failed to verify the signature with bad doughnut", () => {

  });


});