
"use strict";

const API_URL = "http://127.0.0.1:5000";

let scanHistory = [];
let allFindings = [];
let isScanning = false;

const VIEWS = {
    dashboardView: {
        title: "Security Dashboard",
        breadcrumb: "Workspace / Dashboard"
    },
    scanView: {
        title: "Scan Project",
        breadcrumb: "Workspace / Scan Project"
    },
    historyView: {
        title: "Scan History",
        breadcrumb: "Workspace / Scan History"
    },
    findingsView: {
        title: "Security Findings",
        breadcrumb: "Security / Findings"
    },
    settingsView: {
        title: "Settings",
        breadcrumb: "Workspace / Settings"
    }
};


document.addEventListener("DOMContentLoaded", () => {
    setupNavigation();
    setupScanButtons();
    setupHistoryButtons();
    setupFindingControls();
    setupFindingModal();

    showView("dashboardView");
    loadScanHistory();
});


// ============================================
// NAVIGATION
// ============================================

function setupNavigation() {
    document.querySelectorAll(".nav-link").forEach(link => {
        link.addEventListener("click", event => {
            event.preventDefault();

            showView(link.dataset.view);
        });
    });

    document.querySelectorAll("[data-go-view]").forEach(button => {
        button.addEventListener("click", () => {
            showView(button.dataset.goView);
        });
    });
}


function showView(viewId) {
    if (!VIEWS[viewId]) return;

    document.querySelectorAll(".page-view").forEach(view => {
        view.classList.add("hidden-view");
    });

    const selectedView = document.getElementById(viewId);

    if (!selectedView) return;

    selectedView.classList.remove("hidden-view");

    document.querySelectorAll(".nav-link").forEach(link => {
        link.classList.toggle(
            "active",
            link.dataset.view === viewId
        );
    });

    document.getElementById("pageTitle").textContent =
        VIEWS[viewId].title;

    document.getElementById("breadcrumb").textContent =
        VIEWS[viewId].breadcrumb;

    if (viewId === "findingsView") {
        renderFindings();
    }

    if (viewId === "historyView") {
        updateFullHistory();
    }
}


// ============================================
// API
// ============================================

async function apiRequest(endpoint, options = {}) {
    const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        cache: "no-store"
    });

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error("The server returned an invalid response.");
    }

    if (!response.ok) {
        throw new Error(data.error || `Request failed: ${response.status}`);
    }

    return data;
}


// ============================================
// SCAN
// ============================================

function setupScanButtons() {
    document.getElementById("newScanBtn").addEventListener("click", () => {
        showView("scanView");
        document.getElementById("projectPath").focus();
    });

    document.getElementById("scanProjectBtn").addEventListener(
        "click",
        startSecurityScan
    );

    document.getElementById("projectPath").addEventListener(
        "keydown",
        event => {
            if (event.key === "Enter") {
                startSecurityScan();
            }
        }
    );
}


async function startSecurityScan() {
    if (isScanning) return;

    const projectInput = document.getElementById("projectPath");
    const scanButton = document.getElementById("scanProjectBtn");
    const scanMessage = document.getElementById("scanMessage");

    const projectPath = projectInput.value.trim();

    if (!projectPath) {
        scanMessage.textContent = "Please enter a project folder path.";
        return;
    }

    isScanning = true;
    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    scanMessage.className = "message-info";
    scanMessage.textContent = "Analyzing project for exposed secrets...";

    try {
        const result = await apiRequest("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                project_path: projectPath
            })
        });

        scanMessage.className =
            result.status === "PASSED" ? "message-success" : "message-danger";

        scanMessage.textContent =
            `Scan ${result.status}. ${result.total_secrets} secret(s) detected.`;

        await loadScanHistory();

    } catch (error) {
        scanMessage.className = "message-danger";
        scanMessage.textContent = `Error: ${error.message}`;
        console.error("Scan error:", error);

    } finally {
        isScanning = false;
        scanButton.disabled = false;
        scanButton.textContent = "Start Security Scan";
    }
}


// ============================================
// LOAD HISTORY
// ============================================

async function loadScanHistory() {
    try {
        const result = await apiRequest("/api/history");

        if (!Array.isArray(result.history)) {
            throw new Error("Invalid history response.");
        }

        scanHistory = result.history;

        updateDashboardStats();
        updateSecurityOverview();
        updateRecentHistory();
        updateFullHistory();
        buildFindings();

        return true;

    } catch (error) {
        console.error("History loading failed:", error);

        showTableMessage(
            "recentScanHistory",
            5,
            "Unable to load scan history. Check the Flask server."
        );

        showTableMessage(
            "fullScanHistory",
            5,
            "Unable to load scan history."
        );

        showTableMessage(
            "findingsTable",
            6,
            "Unable to load findings."
        );

        return false;
    }
}


// ============================================
// DASHBOARD STATISTICS
// ============================================

function updateDashboardStats() {
    const totalScans = scanHistory.length;

    const totalSecrets = scanHistory.reduce(
        (sum, scan) => sum + Number(scan.total_secrets || 0),
        0
    );

    const secureScans = scanHistory.filter(
        scan => scan.status === "PASSED"
    ).length;

    const failedScans = scanHistory.filter(
        scan => scan.status === "FAILED"
    ).length;

    setText("totalScans", totalScans);
    setText("totalSecrets", totalSecrets);
    setText("secureScans", secureScans);
    setText("failedScans", failedScans);
}


function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


// ============================================
// SECURITY OVERVIEW
// ============================================

function updateSecurityOverview() {
    const container = document.getElementById("securityStatus");

    if (!container) return;

    const icon = container.querySelector(".security-icon");
    const heading = container.querySelector("h2");
    const description = container.querySelector("p");

    if (!scanHistory.length) {
        icon.textContent = "–";
        heading.textContent = "Awaiting First Scan";
        description.textContent = "Run a scan to see your security status.";
        container.dataset.status = "neutral";
        return;
    }

    const latest = scanHistory[0];

    if (latest.status === "PASSED") {
        icon.textContent = "✓";
        heading.textContent = "Project Secure";
        description.textContent = "No secrets detected in the latest scan.";
        container.dataset.status = "passed";
    } else {
        icon.textContent = "!";
        heading.textContent = "Security Issues Detected";
        description.textContent =
            `${latest.total_secrets} potential secret(s) detected in the latest scan.`;
        container.dataset.status = "failed";
    }
}


// ============================================
// HISTORY TABLES
// ============================================

function updateRecentHistory() {
    renderHistoryTable("recentScanHistory", scanHistory.slice(0, 5));
}


function updateFullHistory() {
    renderHistoryTable("fullScanHistory", scanHistory);
}


function renderHistoryTable(tableId, records) {
    const tbody = document.getElementById(tableId);

    if (!tbody) return;

    tbody.replaceChildren();

    if (!records.length) {
        showTableMessage(tableId, 5, "No scan records available.");
        return;
    }

    records.forEach(scan => {
        const row = document.createElement("tr");

        addCell(row, scan.id);
        addCell(row, scan.project_path);
        addCell(row, formatDate(scan.scan_date));
        addCell(row, Number(scan.total_secrets || 0));

        const statusCell = document.createElement("td");
        statusCell.appendChild(createStatusBadge(scan.status));
        row.appendChild(statusCell);

        tbody.appendChild(row);
    });
}


function addCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value ?? "—";
    row.appendChild(cell);
}


function showTableMessage(tableId, columnCount, message) {
    const tbody = document.getElementById(tableId);

    if (!tbody) return;

    tbody.replaceChildren();

    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = columnCount;
    cell.className = "empty-state";
    cell.textContent = message;

    row.appendChild(cell);
    tbody.appendChild(row);
}


function createStatusBadge(status) {
    const badge = document.createElement("span");

    badge.className = `status-badge ${
        status === "PASSED" ? "status-passed" : "status-failed"
    }`;

    badge.textContent = status || "UNKNOWN";

    return badge;
}


function formatDate(value) {
    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? value
        : date.toLocaleString();
}


// ============================================
// FINDINGS
// ============================================

function buildFindings() {
    allFindings = [];

    scanHistory.forEach(scan => {
        const findings = Array.isArray(scan.findings)
            ? scan.findings
            : [];

        findings.forEach((finding, index) => {
            allFindings.push({
                ...finding,
                scanId: scan.id,
                projectPath: scan.project_path,
                scanDate: scan.scan_date,
                scanStatus: scan.status,
                findingIndex: index
            });
        });
    });

    setText("findingsTotal", allFindings.length);

    const affectedScans = new Set(
        allFindings.map(finding => finding.scanId)
    );

    setText("affectedScans", affectedScans.size);

    renderFindings();
}


function setupFindingControls() {
    document.getElementById("findingSearch").addEventListener(
        "input",
        renderFindings
    );

    document.getElementById("findingStatusFilter").addEventListener(
        "change",
        renderFindings
    );

    document.getElementById("refreshFindingsBtn").addEventListener(
        "click",
        async () => {
            await loadScanHistory();
            renderFindings();
        }
    );
}


function renderFindings() {
    const tbody = document.getElementById("findingsTable");

    if (!tbody) return;

    const search = (
        document.getElementById("findingSearch")?.value || ""
    ).trim().toLowerCase();

    const statusFilter =
        document.getElementById("findingStatusFilter")?.value || "ALL";

    const filtered = allFindings.filter(finding => {
        const searchable = [
            finding.RuleID,
            finding.Description,
            finding.File,
            finding.projectPath,
            finding.Commit
        ].join(" ").toLowerCase();

        const matchesSearch = searchable.includes(search);

        const matchesStatus =
            statusFilter === "ALL" ||
            finding.scanStatus === statusFilter;

        return matchesSearch && matchesStatus;
    });

    tbody.replaceChildren();

    if (!filtered.length) {
        showTableMessage(
            "findingsTable",
            6,
            allFindings.length
                ? "No findings match your search or filter."
                : "No saved findings. Run a scan to detect secrets."
        );
        return;
    }

    filtered.forEach(finding => {
        const row = document.createElement("tr");

        addCell(row, finding.scanId);
        addCell(row, finding.RuleID || "Unknown rule");
        addCell(row, finding.File || "Unknown file");
        addCell(row, finding.StartLine ?? "—");
        addCell(row, finding.projectPath || "—");

        const actionCell = document.createElement("td");
        const button = document.createElement("button");

        button.className = "small-button";
        button.textContent = "View Details";

        button.addEventListener("click", () => {
            openFindingDetails(finding);
        });

        actionCell.appendChild(button);
        row.appendChild(actionCell);

        tbody.appendChild(row);
    });
}


// ============================================
// FINDING DETAILS MODAL
// ============================================

function setupFindingModal() {
    const modal = document.getElementById("findingModal");

    document.getElementById("closeFindingModal").addEventListener(
        "click",
        closeFindingDetails
    );

    modal.addEventListener("click", event => {
        if (event.target === modal) {
            closeFindingDetails();
        }
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && !modal.classList.contains("hidden-view")) {
            closeFindingDetails();
        }
    });
}


function openFindingDetails(finding) {
    const modal = document.getElementById("findingModal");
    const details = document.getElementById("findingDetails");

    details.replaceChildren();

    const fields = [
    ["Scan ID", finding.scanId],
    ["Scan Status", finding.scanStatus],
    ["Rule ID", finding.RuleID],
    ["Description", finding.Description],

    // Intelligent Finding Analysis
    ["Risk Level", finding.RiskLevel],
    ["Risk Reason", finding.RiskReason],
    ["Recommended Remediation", finding.Remediation],

    ["Project", finding.projectPath],
    ["File", finding.File],
    ["Start Line", finding.StartLine],
    ["End Line", finding.EndLine],
    ["Start Column", finding.StartColumn],
    ["End Column", finding.EndColumn],
    ["Commit", finding.Commit],
    ["Author", finding.Author],
    ["Detection Date", formatDate(finding.scanDate)],
    ["Fingerprint", finding.Fingerprint],
    ["Secret", "[REDACTED]"],
    ["Matched Content", "[REDACTED]"]
];

    fields.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "detail-item";

        const heading = document.createElement("strong");
        heading.textContent = label;

        const content = document.createElement("span");
        content.textContent =
            value === undefined || value === null || value === ""
                ? "Not available"
                : String(value);

        item.append(heading, content);
        details.appendChild(item);
    });

    modal.classList.remove("hidden-view");
    document.getElementById("closeFindingModal").focus();
}


function closeFindingDetails() {
    document.getElementById("findingModal").classList.add("hidden-view");
}


// ============================================
// HISTORY REFRESH
// ============================================

function setupHistoryButtons() {
    document.getElementById("refreshHistoryBtn").addEventListener(
        "click",
        async () => {
            await loadScanHistory();
        }
    );
}
