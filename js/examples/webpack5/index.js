// const crypto = require('crypto');

// if (global.self !== undefined) {
//   Object.defineProperty(global.self, 'crypto', {
//     value: {
//       getRandomValues: arr => crypto.randomBytes(arr.length)
//     }
//   });
// }

// import('../../libWeb/doughnut.js').then(libWeb => {
//   console.log(`libWeb`, libWeb);
// });

// import('../../pkg/index.js').then(pkg => {
//   console.log(`pkg`, pkg);
// });

const rust = import('../../pkg/index.js');

rust.then(r => {
  r.say_hello_from_rust();
  console.log('*********** webpack 5');
})
  .catch(console.error);

