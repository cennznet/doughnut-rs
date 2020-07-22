/**
 * Example: https://github.com/steelx/rust-wasm-boilerplate
 */
const webpack = require('webpack');
const WasmPackPlugin = require('@wasm-tool/wasm-pack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const path = require('path');

module.exports = (env, args) => {
  const isProduction = (args.mode === 'production');//package.json scripts -> build

  return {
    entry: './index.js',
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: isProduction ? '[name].[contenthash].js' : '[name].[hash].js'
    },
    plugins: [
      new HtmlWebpackPlugin({
        filename: 'index.html',
        template: './index.template.html'
      }),
      new WasmPackPlugin({
        crateDirectory: path.resolve(__dirname, ".")// (where the cargo.toml file is located)
      }),
      new webpack.ProvidePlugin({
        TextDecoder: ['text-encoding', 'TextDecoder'],
        TextEncoder: ['text-encoding', 'TextEncoder'],
      }),
    ],
  }
};
