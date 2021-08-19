const path = require('path');
const webpack = require("webpack");

module.exports = {
    mode: 'production',
    entry: './js/AuthorizationRequest.js',
    resolve: {
        alias: {
            jquery: path.resolve(__dirname, 'js/jquery-3.6.0.min'),
        }
    },
    output: {
        path: path.resolve(__dirname, 'js'),
        filename: 'bundle.js',
    },
    plugins: [
        new webpack.ProvidePlugin({
            $: "jquery",
            jQuery: "jquery"
        })
    ]
};