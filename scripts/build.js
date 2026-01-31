const fs = require('fs');
const path = require('path');
const { marked } = require('marked');

// Configuration
const POSTS_DIR = path.join(__dirname, '../posts');
const OUTPUT_DIR = path.join(__dirname, '../blog');
const TEMPLATE_PATH = path.join(__dirname, '../templates/post.html');

// Ensure output dir exists
if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Read template
const template = fs.readFileSync(TEMPLATE_PATH, 'utf8');

// Process files
fs.readdirSync(POSTS_DIR).forEach(file => {
    if (path.extname(file) === '.md') {
        const filePath = path.join(POSTS_DIR, file);
        const content = fs.readFileSync(filePath, 'utf8');

        // Extract Title (first h1 or filename)
        let title = file.replace('.md', '');
        const titleMatch = content.match(/^# (.*$)/m);
        if (titleMatch) {
            title = titleMatch[1];
        }

        // Convert MD to HTML
        const htmlContent = marked.parse(content);

        // Generate Metadata Block (Box Style)
        const dateStr = new Date().toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
        const metadata = [
            { label: 'FILE', value: file },
            { label: 'DATE', value: dateStr },
            { label: 'AUTHOR', value: 'coili' }
        ];

        // Box Configuration
        const boxWidth = 52; // Inner width
        const borderTop = ' ┌────── FILE INFO ' + '─'.repeat(boxWidth - 19) + '┐';
        const borderBot = ' └' + '─'.repeat(boxWidth) + '┘';
        const emptyLine = ' │' + ' '.repeat(boxWidth) + '│';

        // Content Lines
        const contentLines = metadata.map(m => {
            // Format: "   LABEL........: Value"
            const prefix = `   ${m.label}`;
            const dotsCount = 16 - prefix.length; // Align colons at specific char
            const dots = '.'.repeat(dotsCount > 0 ? dotsCount : 0);

            let lineContent = `${prefix}${dots}: ${m.value}`;

            // Pad the right side to fit box
            const padding = boxWidth - lineContent.length;
            if (padding < 0) {
                // Truncate if too long (rare)
                lineContent = lineContent.substring(0, boxWidth - 3) + '...';
                return ' │' + lineContent + '│';
            }
            return ' │' + lineContent + ' '.repeat(padding) + '│';
        });

        const metadataBlock = [
            borderTop,
            emptyLine,
            ...contentLines,
            emptyLine,
            borderBot
        ].join('\n');

        // Inject into template
        let output = template
            .replace(/{{TITLE}}/g, title)
            .replace(/{{METADATA_BLOCK}}/g, metadataBlock) // Replaces the whole block in template
            .replace(/{{CONTENT}}/g, htmlContent);

        // Save
        const outputFilename = file.replace('.md', '.html');
        fs.writeFileSync(path.join(OUTPUT_DIR, outputFilename), output);
        console.log(`[+] Generated: blog/${outputFilename}`);
    }
});

// Generate Index (Optional - simple list)
let indexHtml = `<!DOCTYPE html><html><head><link rel="stylesheet" href="../style.css"></head><body><pre>
<span style="color: #555;">/* INDEX OF /blog/ */</span>

`;
fs.readdirSync(OUTPUT_DIR).forEach(file => {
    if (file !== 'index.html' && file.endsWith('.html')) {
        indexHtml += `<a href="${file}">[FILE] ${file}</a>\n`;
    }
});
indexHtml += `\n<a href="../index.html">[..] Back</a></pre></body></html>`;
fs.writeFileSync(path.join(OUTPUT_DIR, 'index.html'), indexHtml);
console.log('[+] Index generated.');
