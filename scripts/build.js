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

        // Extract Title and Category
        let title = file.replace('.md', '');
        let category = 'Uncategorized'; // Default

        const titleMatch = content.match(/^# (.*$)/m);
        if (titleMatch) {
            title = titleMatch[1];
        }

        const categoryMatch = content.match(/^Category:\s*(.*)$/m);
        if (categoryMatch) {
            category = categoryMatch[1].trim();
        }

        // Convert MD to HTML
        // Remove the Category line from content to avoid displaying it twice
        const cleanContent = content.replace(/^Category:\s*(.*)$/m, '');
        const htmlContent = marked.parse(cleanContent);

        // Generate Metadata Block (Box Style)
        const dateStr = new Date().toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
        const metadata = [
            { label: 'FILE', value: file },
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
            // Calculate raw lengths for alignment
            const prefix = `   ${m.label}`;
            const dotsCount = 16 - prefix.length;
            const dots = '.'.repeat(dotsCount > 0 ? dotsCount : 0);

            // Raw content for padding calc
            const rawContent = `${prefix}${dots}: ${m.value}`;
            const padding = boxWidth - rawContent.length;
            const safePadding = padding >= 0 ? padding : 0;

            // HTML Styled Content
            // Format: "   <span class="key">LABEL</span>......: <span class="val">Value</span>"
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

        // Inject into template
        // Add cache buster to CSS to force reload
        const cacheBuster = Date.now();
        l = template.replace('href="../style.css"', `href="../style.css?v=${cacheBuster}"`);

        let output = l
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
