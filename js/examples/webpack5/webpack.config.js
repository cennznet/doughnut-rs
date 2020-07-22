const path = require('path');
const webpack = require('webpack');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const WasmPackPlugin = require('@wasm-tool/wasm-pack-plugin');

module.exports = {
  mode: 'development',
  devtool: 'eval-cheap-module-source-map',
  entry: './index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.js',
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        loader: 'babel-loader',
      },
      {
        test: /\.html/,
        use: ['html-loader']
      },
      {
        test: /\.wasm$/,
        type: "webassembly/async"
      }
    ],
  },
  optimization: {
    chunkIds: "deterministic" // To keep filename consistent between different modes (for example building only)
  },
  experiments: {
    asyncWebAssembly: true,
    importAwait: true
  },
  plugins: [
    new HtmlWebpackPlugin({
      filename: 'index.html',
      template: 'index.template.html'
    }),
    new WasmPackPlugin({
      crateDirectory: path.resolve(__dirname, "..")
    }),
    // new webpack.ProvidePlugin({
    //   TextDecoder: ['text-encoding', 'TextDecoder'],
    //   TextEncoder: ['text-encoding', 'TextEncoder']
    // })
  ],
};
