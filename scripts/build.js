const fs = require('fs');
const path = require('path');
const { marked } = require('marked');
const { markedHighlight } = require('marked-highlight');
const hljs = require('highlight.js');

const POSTS_DIR = path.join(__dirname, '../posts');
const OUTPUT_DIR = path.join(__dirname, '../blog');
const TEMPLATE_PATH = path.join(__dirname, '../templates/post.html');

marked.use(markedHighlight({
    langPrefix: 'hljs language-',
    highlight(code, lang) {
        const language = hljs.getLanguage(lang) ? lang : 'plaintext';
        return hljs.highlight(code, { language }).value;
    }
}));

if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

const template = fs.readFileSync(TEMPLATE_PATH, 'utf8');

function walkDir(dir, callback) {
    fs.readdirSync(dir).forEach(f => {
        let dirPath = path.join(dir, f);
        let isDirectory = fs.statSync(dirPath).isDirectory();
        isDirectory ? walkDir(dirPath, callback) : callback(path.join(dir, f));
    });
}

const generatedPosts = [];

walkDir(POSTS_DIR, (filePath) => {
    const relativePath = path.relative(POSTS_DIR, filePath);
    const outputFilePath = path.join(OUTPUT_DIR, relativePath);
    const outputDir = path.dirname(outputFilePath);

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    if (path.extname(filePath) === '.md') {
        let content = fs.readFileSync(filePath, 'utf8');

        let title = path.basename(filePath).replace('.md', '');
        let category = 'Uncategorized';

        const titleMatch = content.match(/^# (.*$)/m);
        if (titleMatch) {
            title = titleMatch[1];
        }

        const categoryMatch = content.match(/^Category:\s*(.*)$/m);
        if (categoryMatch) {
            category = categoryMatch[1].trim();
        }

        content = content.replace(/!\[\[(.*?)\]\]/g, (match, p1) => {
            const cleanPath = p1.replace(/\\/g, '/');
            return `![](${cleanPath})`;
        });

        content = content.replace(/^(\*\*.*?;)\s*$/gm, '$1  ');

        const cleanContent = content.replace(/^Category:\s*(.*)$/m, '');
        const htmlContent = marked.parse(cleanContent);

        const dateStr = new Date().toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
        const metadata = [
            { label: 'FILE', value: path.basename(filePath) },
            { label: 'DATE', value: dateStr },
            { label: 'AUTHOR', value: 'coili' },
            { label: 'CAT', value: category }
        ];

        const boxWidth = 52;
        const borderTop = ' <span class="box-border">╔══════</span> <span class="val">FILE INFO</span> <span class="box-border">' + '═'.repeat(boxWidth - 17) + '╗</span>';
        const borderBot = ' <span class="box-border">╚' + '═'.repeat(boxWidth) + '╝</span>';
        const emptyLine = ' <span class="box-border">║' + ' '.repeat(boxWidth) + '║</span>';

        const contentLines = metadata.map(m => {
            const prefix = `   ${m.label}`;
            const dotsCount = 16 - prefix.length;
            const dots = '.'.repeat(dotsCount > 0 ? dotsCount : 0);

            const rawContent = `${prefix}${dots}: ${m.value}`;
            const padding = boxWidth - rawContent.length;
            const safePadding = padding >= 0 ? padding : 0;

            const styledContent = `   <span class="key">${m.label}</span>${dots}<span class="box-border">:</span> <span class="val">${m.value}</span>` + ' '.repeat(safePadding);

            return ' <span class="box-border">║</span>' + styledContent + '<span class="box-border">║</span>';
        });

        const metadataBlock = [
            borderTop,
            emptyLine,
            ...contentLines,
            emptyLine,
            borderBot
        ].join('\n');

        const depth = relativePath.split(path.sep).length - 1;
        const cssPath = '../'.repeat(depth + 1) + 'style.css';

        const cacheBuster = Date.now();
        const outputWithCache = template.replace('href="../style.css"', `href="${cssPath}?v=${cacheBuster}"`);

        const rootPath = '../'.repeat(depth) + 'index.html';
        let output = outputWithCache
            .replace(/href="\.\.\/index\.html"/g, `href="${rootPath}"`)
            .replace(/{{TITLE}}/g, title)
            .replace(/{{METADATA_BLOCK}}/g, metadataBlock)
            .replace(/{{CONTENT}}/g, htmlContent);

        const finalOutputFilename = outputFilePath.replace('.md', '.html');
        fs.writeFileSync(finalOutputFilename, output);
        console.log(`[+] Generated: ${path.relative(process.cwd(), finalOutputFilename)}`);

        generatedPosts.push({
            path: relativePath.replace('.md', '.html').replace(/\\/g, '/'),
            title: title
        });

    } else {
        fs.copyFileSync(filePath, outputFilePath);
        console.log(`[>] Copied asset: ${relativePath}`);
    }
});

// Generate Index
const boxWidth = 52;
const borderTopI = ' <span class="box-border">┌────── MENU ────────────────────────────────────────┐</span>';
const borderBotI = ' <span class="box-border">└' + '─'.repeat(boxWidth) + '┘</span>';
const emptyLineI = ' <span class="box-border">│</span>' + ' '.repeat(boxWidth) + '<span class="box-border">│</span>';

let menuContent = '';
generatedPosts.forEach((post, index) => {
    // Format: "   [0x01]... "
    const hexIndex = (index + 1).toString(16).padStart(2, '0').toUpperCase();
    const prefix = `   [0x${hexIndex}]... `;

    // Link: <a href="path">Title</a>
    const linkStr = `<a href="${post.path}">${post.title}</a>`;

    // For padding calculation, we need length of visible text
    // "   [0x01]... Title"
    const visibleLen = prefix.length + post.title.length;
    const padding = boxWidth - visibleLen;
    const safePadding = padding >= 0 ? padding : 0;

    menuContent += ' <span class="box-border">│</span>' + prefix + linkStr + ' '.repeat(safePadding) + '<span class="box-border">│</span>\n';
});

let indexHtml = `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Blog Index</title>
    <link rel="stylesheet" href="../style.css?v=${Date.now()}">
</head>
<body>
    <pre style="text-align: center;">

<span style="color: #555;">/* INDEX OF /blog/ */</span>

${borderTopI}
${emptyLineI}
${menuContent}${emptyLineI}
${borderBotI}

<a href="../index.html">[..] Back</a>
    </pre>
</body>
</html>`;

fs.writeFileSync(path.join(OUTPUT_DIR, 'index.html'), indexHtml);
console.log('[+] Index generated.');