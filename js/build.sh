# go root folder
cd .. 

# compile the rust codebase
wasm-pack build --target nodejs --scope cennznet --out-name doughnut --out-dir ./js/lib

# go to sdk folder
cd ./js/lib

# export DoughnutHandle as default
sed -i -e 's/module.exports.DoughnutHandle/module.exports.Doughnut/g' doughnut.js

# replace README.md with javascript sdk version
cp -rf ../README.md .
