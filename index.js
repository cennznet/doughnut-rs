// Note that a dynamic `import` statement here is required due to
// // webpack/webpack#6615, but in theory `import { greet } from './pkg/hello_world';`
// // will work here one day as well!
const Doughnut = require('./pkg/doughnut_rs.js').DoughnutHandle;

let d = Doughnut.new();
console.log(d);
console.log(d.holder(new Uint8Array([1,2,3,4,5,6,7,8,9,10])));
d.holder()
