<to be updated>
# @trn/doughnut-wasm

Wasm Doughnut codec and maker.
Currently compliant with the version 0 spec.  

## Create a Doughnut (unsigned)

```js
const Doughnut = require('@trn/doughnut-wasm').default;

const issuer = new Uint8Array(32);
const holder = new Uint8Array(32);
const expiry = 100;
const notBefore = 1;

return new Doughnut(issuer, holder, expiry, notBefore).addDomain('example', [1, 2, 3]);
```

## Verify Doughnut

Check a doughnut is:
- valid for use by `holder` at unix timestamp `when`
- correctly signed by the `issuer`
Note: this does not verify the terms of embedded permission domains.

```js
const doughnut = new Doughnut(...);
doughnut.verify(holder, now);
```

## Inspect Doughnut Fields

Getter functions for inspecting a doughnut

```js
const d = new Doughnut(...);
const doughnut = {
  issuer: d.issuer(),
  holder: d.holder(),
  expiry: d.expiry(),
  not_before: d.notBefore(),
  signature_version: d.signatureVersion(),
  payload_version: d.payloadVersion(),
}
// query permission domain bytes
// It will throw 'undefined' if the domain does not exist
let testDomain = d.domain("test");
```

## Doughnut Encoding and Decoding

`Encoding`: Encode a doughnut object

`Decoding`: Create a doughnut object from a encoded doughnut

```js
const Doughnut = require('@trn/doughnut-wasm').default;

const payload = [64, 24, 64, 22, 126, 150, 15, 176, 190, ..., 235, 3, 21, 63, 79, 192, 137, 6];
const doughnut = Doughnut.decode();
doughnut.issuer();

const doughnut = new Doughnut(...);
const encoded = doughnut.encode();
```

## Signing Doughnuts

This package provides some convenience functions for signing doughnuts

```js
const Doughnut = require('@trn/doughnut-wasm').default;
let doughnut = new Doughnut(...);
// Schnorrkel
doughnut.signSr25519(<sr25519 secret key bytes>);
// or Edwards
doughnut.signEd25519(<ed25519 secret key bytes>);

console.log(doughnut.signature)
```

Sign with Ed25519 method using a `tweetnacl` keypair
```js
const Doughnut = require('@trn/doughnut-wasm').default;
const nacl = require('tweetnacl');

let issuer = nacl.box.keyPair();
let holder = nacl.box.keyPair();
let doughnut = new Doughnut(issuer.publicKey, holder.publicKey, 1, 1);
doughnut.signEd25519(issuer.secretKey);
console.log(d.signature());
```

Sign with schnorrkel method using a `@polkadot/util-crypto` keypair.
Note: @polkadot/util-crypto also provides similar ed25519 methods.
```js
const Doughnut = require('@trn/doughnut-wasm').default;
const utilCrypto = require('@polkadot/util-crypto');
const crypto = require('crypto');

utilCrypto.cryptoWaitReady().then(() => {
  let issuer = utilCrypto.schnorrkelKeypairFromSeed(crypto.randomBytes(32));
  let doughnut = new Doughnut(issuer.publicKey, holder.publicKey, 1, 1);
  doughnut.signSr25519(issuer.secretKey);
  console.log(doughnut.signature());
});
```
