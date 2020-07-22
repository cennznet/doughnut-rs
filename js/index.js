/**
 * wasm-pack generates pkg folder
 */
const rust = import('./pkg/index.js');

rust.then(r => {
  r.say_hello_from_rust();
  console.log('*********** wasm ***********');
})
  .catch(console.error);

