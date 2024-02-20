# @therootnetwork/doughnut-nodejs

Wasm Doughnut codec and maker.
Currently compliant with the version 0, 1 spec.  

## Create a Doughnut (unsigned)

```js
const Doughnut = require('@therootnetwork/doughnut-nodejs').Doughnut;
const { SignatureVersion,  PayloadVersion, FeeMode } = require("@therootnetwork/doughnut-nodejs");

const issuer = new Uint8Array(33);
const holder = new Uint8Array(33);
const expiry = 100;
const notBefore = 1;

return new Doughnut( PayloadVersion.V1, issuer, holder, FeeMode.ISSUER, expiry, notBefore).addTopping('trn', [1, 2, 3]);
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
// query topping bytes
// It will throw 'undefined' if the topping does not exist
let testDomain = d.topping("trn");
```

## Doughnut Encoding and Decoding

`Encoding`: Encode a doughnut object

`Decoding`: Create a doughnut object from a encoded doughnut

```js
const Doughnut = require('@therootnetwork/doughnut-nodejs').default;

const payload = [64, 24, 64, 22, 126, 150, 15, 176, 190, ..., 235, 3, 21, 63, 79, 192, 137, 6];
const doughnut = Doughnut.decode();
doughnut.issuer();

const doughnut = new Doughnut(...);
const encoded = doughnut.encode();
```

## Signing Doughnuts

This package provides some convenience functions for signing doughnuts

```js
const Doughnut = require('@therootnetwork/doughnut-nodejs').default;
let doughnut = new Doughnut(...);
// ECDSA
doughnut.signECDSA(<ECDSA secret key bytes>);
// or EIP191
doughnut.signEIP191(<EIP191 secret key bytes>);

console.log(doughnut.signature)
```
