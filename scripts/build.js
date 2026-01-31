const fs = require('fs');
const path = require('path');
const { marked } = require('marked');
const { markedHighlight } = require('marked-highlight');
const hljs = require('highlight.js');

// Configuration
const POSTS_DIR = path.join(__dirname, '../posts');
const OUTPUT_DIR = path.join(__dirname, '../blog');
const TEMPLATE_PATH = path.join(__dirname, '../templates/post.html');

// Configure Marked with Highlight.js
marked.use(markedHighlight({
    langPrefix: 'hljs language-',
    highlight(code, lang) {
        const language = hljs.getLanguage(lang) ? lang : 'plaintext';
        return hljs.highlight(code, { language }).value;
    }
}));

// Ensure output dir exists
if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Read template
const template = fs.readFileSync(TEMPLATE_PATH, 'utf8');

// Recursive function to walk directories
function walkDir(dir, callback) {
    fs.readdirSync(dir).forEach(f => {
        let dirPath = path.join(dir, f);
        let isDirectory = fs.statSync(dirPath).isDirectory();
        isDirectory ? walkDir(dirPath, callback) : callback(path.join(dir, f));
    });
}

// Track generated files for index
const generatedPosts = [];

// Process files
walkDir(POSTS_DIR, (filePath) => {
    const relativePath = path.relative(POSTS_DIR, filePath);
    const outputFilePath = path.join(OUTPUT_DIR, relativePath);
    const outputDir = path.dirname(outputFilePath);

    // Ensure target subdirectory exists
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    if (path.extname(filePath) === '.md') {
        // Process Markdown
        let content = fs.readFileSync(filePath, 'utf8');

        // Extract Title and Category
        let title = path.basename(filePath).replace('.md', '');
        let category = 'Uncategorized'; // Default

        const titleMatch = content.match(/^# (.*$)/m);
        if (titleMatch) {
            title = titleMatch[1];
        }

        const categoryMatch = content.match(/^Category:\s*(.*)$/m);
        if (categoryMatch) {
            category = categoryMatch[1].trim();
        }

        // Support Obsidian-style images ![[path]] -> ![](path) and fix backslashes
        content = content.replace(/!\[\[(.*?)\]\]/g, (match, p1) => {
            const cleanPath = p1.replace(/\\/g, '/');
            return `![](${cleanPath})`;
        });

        // Convert MD to HTML
        const cleanContent = content.replace(/^Category:\s*(.*)$/m, '');
        const htmlContent = marked.parse(cleanContent);

        // Generate Metadata Block (Box Style)
        const dateStr = new Date().toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
        const metadata = [
            { label: 'FILE', value: path.basename(filePath) },
            { label: 'DATE', value: dateStr },
            { label: 'AUTHOR', value: 'coili' },
            { label: 'CAT', value: category }
        ];

        // Box Configuration
        const boxWidth = 52; // Inner width
        const borderTop = ' <span class="box-border">╔══════</span> <span class="val">FILE INFO</span> <span class="box-border">' + '═'.repeat(boxWidth - 17) + '╗</span>';
        const borderBot = ' <span class="box-border">╚' + '═'.repeat(boxWidth) + '╝</span>';
        const emptyLine = ' <span class="box-border">║' + ' '.repeat(boxWidth) + '║</span>';

        // Content Lines
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

        // Calculate depth for CSS path adjustment
        // blog/file.html -> depth 0 -> ../style.css
        // blog/subdir/file.html -> depth 1 -> ../../style.css
        const depth = relativePath.split(path.sep).length - 1;
        const cssPath = '../'.repeat(depth + 1) + 'style.css';

        // Add cache buster
        const cacheBuster = Date.now();
        const outputWithCache = template.replace('href="../style.css"', `href="${cssPath}?v=${cacheBuster}"`);

        // Fix "Back to root" links based on depth
        const rootPath = '../'.repeat(depth) + 'index.html';
        // Note: The template has hardcoded [..] Back to root pointing to ../index.html
        // We might want to fix this dynamically too, but for now let's handle CSS.
        // Actually, let's fix the back link too.
        let output = outputWithCache
            .replace(/href="\.\.\/index\.html"/g, `href="${rootPath}"`)
            .replace(/{{TITLE}}/g, title)
            .replace(/{{METADATA_BLOCK}}/g, metadataBlock)
            .replace(/{{CONTENT}}/g, htmlContent);

        const finalOutputFilename = outputFilePath.replace('.md', '.html');
        fs.writeFileSync(finalOutputFilename, output);
        console.log(`[+] Generated: ${path.relative(process.cwd(), finalOutputFilename)}`);

        // Add to index list (relative to blog root)
        generatedPosts.push({
            path: relativePath.replace('.md', '.html').replace(/\\/g, '/'),
            title: title
        });

    } else {
        // Copy other assets (images, etc)
        fs.copyFileSync(filePath, outputFilePath);
        console.log(`[>] Copied asset: ${relativePath}`);
    }
});

// Generate Index
// Simple index at blog/index.html listing all posts recursively
let indexHtml = `<!DOCTYPE html><html><head><link rel="stylesheet" href="../style.css?v=${Date.now()}"></head><body><pre>
<span style="color: #555;">/* INDEX OF /blog/ */</span>

`;
generatedPosts.forEach(post => {
    indexHtml += `<a href="${post.path}">[FILE] ${post.path}</a>\n`; // post.path includes subfolders
});
indexHtml += `\n<a href="../index.html">[..] Back</a></pre></body></html>`;
fs.writeFileSync(path.join(OUTPUT_DIR, 'index.html'), indexHtml);
console.log('[+] Index generated.');