// Check import works from pure node runtime.
// The test runtime, jest, does not guarantee this alone.
const process = require('process');
try {
  const Doughnut = require('../libNode/doughnut').Doughnut;
} catch (e) {
  console.log(e);
  process.exit(1);
}
process.exit(0);

