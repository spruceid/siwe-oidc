const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const path = require('path');
const webpack = require('webpack');
const HTMLWebpackPlugin = require('html-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');

const mode = process.env.NODE_ENV || 'development';
const prod = mode === 'production';

module.exports = {
    entry: {
        'bundle': ['./src/main.tsx']
    },
    resolve: {
        mainFields: ['browser', 'module', 'main'],
        extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs'],
        fallback: {
            assert: require.resolve("assert"),
            buffer: require.resolve('buffer/'),
            crypto: require.resolve('crypto-browserify'),
            fs: false,
            http: require.resolve('stream-http'),
            https: require.resolve('https-browserify'),
            os: require.resolve('os-browserify/browser'),
            path: false,
            process: require.resolve('process/browser'),
            stream: require.resolve('stream-browserify'),
            url: require.resolve("url")
        }
    },
    optimization: {
        runtimeChunk: 'single',
    },
    output: {
        path: prod ? path.join(__dirname, './dist/build') : path.join(__dirname, './dist'),
        filename: '[name].[chunkhash].js',
        chunkFilename: '[name].[chunkhash].[id].js'
    },
    module: {
        rules: [
            {
                test: /\.(ts|tsx)$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-env', '@babel/preset-react', '@babel/preset-typescript']
                    }
                }
            },
            {
                test: /\.svg$/,
                use: [
                    {
                        loader: 'svg-url-loader',
                        options: {
                            limit: 10000,
                        },
                    },
                ],
            },
            {
                test: /\.css$/,
                use: [
                    MiniCssExtractPlugin.loader,
                    'css-loader',
                    'postcss-loader'
                ]
            }
        ]
    },
    mode,
    plugins: [
        new HTMLWebpackPlugin({
            template: path.join(__dirname, 'index.html'),
            filename: path.join(__dirname, './dist/index.html'),
        }),
        new webpack.ProvidePlugin({
            Buffer: ["buffer", "Buffer"],
            process: path.resolve(path.join(__dirname, "node_modules/process/browser.js")),
        }),
        new MiniCssExtractPlugin({
            filename: '[name].[contenthash].css'
        }),
        new webpack.EnvironmentPlugin(prod ? ['INFURA_ID', 'WALLET_CONNECT_ID'] : []),
        new CopyWebpackPlugin({
            patterns: [
                { from: 'favicon.png', to: path.join(__dirname, './dist/favicon.png') },
                { from: 'error.html', to: path.join(__dirname, './dist/error.html') },
            ],
        }),
    ],
    devtool: prod ? false : 'source-map',
    devServer: {
        hot: true,
        open: true,
        static: {
            directory: path.join(__dirname, './dist'),
        },
    }
};
