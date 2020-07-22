// import('../../libWeb/doughnut.js').then(libWeb => {
//   console.log(`libWeb`, libWeb);
// });

// import('../../pkg/index.js').then(pkg => {
//   console.log(`pkg`, pkg);
// });

const rust = import('../../pkg/index.js');

rust.then(r => {
  r.say_hello_from_rust();
  console.log('*********** webpack 4');
})
  .catch(console.error);

