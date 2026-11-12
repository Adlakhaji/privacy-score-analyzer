async function analyzeWebsite() {

    const url = document.getElementById("website").value.trim();

    const result = document.getElementById("result");

    if (!url) {
        result.innerText = "Please enter a website URL.";
        return;
    }

    result.innerText = "Scanning website... Please wait.";

    try {

        const response = await fetch("/api/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Scanning failed.");
        }

        const score = data.score_results["Privacy Score"];

        const breakdown = data.score_results["Breakdown"];

        result.innerHTML = `
            <h2>Privacy Analysis Complete</h2>

            <h1>Privacy Score: ${score}/100</h1>

            <h3>Score Breakdown</h3>

            ${Object.entries(breakdown).map(([name, points]) => `
                <p>${name}: ${points}</p>
            `).join("")}

            <h3>Detailed Results</h3>

            <pre>${JSON.stringify(data.scan_results, null, 2)}</pre>
        `;

    }

    catch (error) {

        result.innerText = error.message;

    }
}
