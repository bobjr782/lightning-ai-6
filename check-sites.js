const { chromium } = require("playwright");

const base = "https://lightning-ai-6.ray-collier264.workers.dev";

const pages = [
    { name: "Homepage", url: `${base}/` },
    { name: "About", url: `${base}/index.html` },
    { name: "Lightning App", url: `${base}/lightning.html` },
    { name: "Licences", url: `${base}/LICENSES.txt` }
];

(async () => {
    const browser = await chromium.launch({ headless: true });

    for (const site of pages) {
        const page = await browser.newPage();
        const errors = [];

        page.on("pageerror", error => errors.push(error.message));

        console.log("\n================================");
        console.log("TESTING: " + site.name);
        console.log("================================");

        try {
            const response = await page.goto(site.url, {
                waitUntil: "domcontentloaded",
                timeout: 30000
            });

            console.log("URL:", site.url);
            console.log("HTTP STATUS:", response.status());
            console.log("PAGE TITLE:", await page.title());

            const text = await page.locator("body").innerText();
            console.log("PAGE CONTENT:", text.substring(0, 500));

            if (response.status() === 404) {
                console.log("RESULT: FAILED - PAGE NOT FOUND");
            } else if (response.status() >= 400) {
                console.log("RESULT: FAILED - SERVER ERROR");
            } else {
                console.log("RESULT: PAGE LOADED");
            }

            if (errors.length) {
                console.log("JAVASCRIPT ERRORS:", errors);
            }

        } catch (error) {
            console.log("RESULT: FAILED");
            console.log(error.message);
        }

        await page.close();
    }

    await browser.close();
})();
