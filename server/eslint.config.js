import unusedImports from 'eslint-plugin-unused-imports';

// $ npx eslint --fix ./

export default [
    {
        files: ["**/*.js"],
        ignores: ["**/node_modules/**"],
        plugins: {
            "unused-imports": unusedImports
        },
        rules: {
            "no-unused-vars": "off",
            "unused-imports/no-unused-imports": "error",
            "unused-imports/no-unused-vars": [
                "warn",
                {
                    vars: "all",
                    args: "after-used",
                    ignoreRestSiblings: true
                }
            ]
        }
    }
];