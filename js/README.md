# doughnut-js

Javacript API for doughnut.
Currently compliant with version 0 spec.  

## Create Doughnut

```js
const Doughnut = require('plug-doughnut').Doughnut;

const issuer = new Uint8Array(32);
const holder = new Uint8Array(32);
const expiry = 100;
const not_before = 1;

const create_doughnut = (issuer) => {
  return Doughnut
    .new(issuer, holder, expiry, not_before)
    .add_payload_version(1)
    .add_domain('cennznet', [1, 2, 3])
    .add_domain('centrapay', [4, 5, 6]);
};
```

## Sign and Verify Doughnut

Sign the doughnut payload with `ED25519` or `SR25519`

- SR25519  Signature Sersion is: `0` (as default);
- ED25519 Signature Sersion is: `1`

```js
const { publicKey, secretKey } = create_sr25519_keypair();
const doughnut = create_doughnut(publicKey).sign(secretKey);
doughnut.verify();

const { publicKey, secretKey } = create_ed25519_keypair();
const doughnut = create_doughnut(publicKey).add_signature_version(1).sign(secretKey);
doughnut.verify();
```

## Check Doughnut

Check a doughnut is valid to be used by a user (`who`) at a timestamp (`when`).  

```js
const doughnut = create_doughnut(issuer);
doughnut.validate(issuser, 16);
```

## Get Doughnut Fields

Getter funtions to get all the fields in doughnut

```js
const d = create_doughnut(issuer)..sign(secretKey);
const doughnut = {
  issuer: d.issuer(),
  holder: d.holder(),
  expiry: d.expiry(),
  not_before: d.not_before(),
  signature_version: d.signature_version(),
  payload_version: d.payload_version(),
}
```

## Doughnut Encoding and Decoding

`Encoding`: encode doughnut object

`Decoding`: create doughnut object from a encoded doughnut

```js
const Doughnut = require('plug-doughnut').Doughnut;

const payload = [64, 24, 64, 22, 126, 150, 15, 176, 190, ..., 235, 3, 21, 63, 79, 192, 137, 6];
const doughnut = Doughnut.decode();
doughnut.issuser();


const doughnut = create_doughnut(issuer);
const encoded_d = doughnut.encode();
```
