module.exports = {
    upgrade: true,
    reject: [
        // only works as ESM
        'chai',
        'eslint-config-prettier',
        // api changes
        'eslint'
    ]
};
