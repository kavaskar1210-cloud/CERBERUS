import { useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

const OWASP_API_TOP_10 = [
  { id: "API1", name: "Broken Object Level Authorization" },
  { id: "API2", name: "Broken Authentication" },
  { id: "API3", name: "Broken Object Property Level Authorization" },
  { id: "API4", name: "Unrestricted Resource Consumption" },
  { id: "API5", name: "Broken Function Level Authorization" },
  { id: "API6", name: "Unrestricted Access to Sensitive Business Flows" },
  { id: "API7", name: "Server-Side Request Forgery" },
  { id: "API8", name: "Security Misconfiguration" },
  { id: "API9", name: "Improper Inventory Management" },
  { id: "API10", name: "Unsafe Consumption of APIs" },
];


function App() {

  const [page, setPage] = useState("dashboard");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [loggedIn, setLoggedIn] = useState(false);
  const [token, setToken] = useState("");

  const [targetUrl, setTargetUrl] = useState("");
  const [scanResult, setScanResult] = useState(null);

  const [apiUrl, setApiUrl] = useState("");
  const [openapiUrl, setOpenapiUrl] = useState("");
  const [apiScanResult, setApiScanResult] = useState(null);

  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);

  const [eventType, setEventType] = useState("");
  const [eventSeverity, setEventSeverity] = useState("medium");
  const [eventMessage, setEventMessage] = useState("");
  const [eventSource, setEventSource] = useState("");
  const [eventSourceIp, setEventSourceIp] = useState("");

  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentSeverity, setIncidentSeverity] = useState("medium");
  const [incidentDescription, setIncidentDescription] = useState("");

  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [investigationFindings, setInvestigationFindings] = useState("");
  const [responseAction, setResponseAction] = useState("");
  const [incidentActionLoading, setIncidentActionLoading] = useState(false);

  const [loading, setLoading] = useState(false);
  const [apiLoading, setApiLoading] = useState(false);
  const [loginLoading, setLoginLoading] = useState(false);

  const [operationsLoading, setOperationsLoading] = useState(false);
  const [eventLoading, setEventLoading] = useState(false);
  const [incidentLoading, setIncidentLoading] = useState(false);

  const [error, setError] = useState("");
  const [operationsMessage, setOperationsMessage] = useState("");


  /* =========================================================
     LOGIN
     ========================================================= */

  async function login() {

    setError("");
    setLoginLoading(true);

    try {

      const body = new URLSearchParams();

      body.append("username", username);
      body.append("password", password);

      const response = await fetch(
        `${API_BASE}/auth/login`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded",
          },
          body,
        }
      );

      const data = await response.json();

      if (!response.ok) {

        throw new Error(
          data.detail || "Login failed"
        );
      }

      setToken(data.access_token);
      setLoggedIn(true);
      setPage("dashboard");

    } catch (err) {

      setError(
        err.message ||
        "Unable to connect to CERBERUS"
      );

    } finally {

      setLoginLoading(false);
    }
  }


  /* =========================================================
     WEB SECURITY SCAN
     ========================================================= */

  async function runWebScan() {

    setError("");
    setScanResult(null);

    if (!targetUrl.trim()) {

      setError(
        "Please enter a target URL."
      );

      return;
    }

    setLoading(true);

    try {

      const response = await fetch(
        `${API_BASE}/web-security/scan`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${token}`,
          },

          body: JSON.stringify({
            url: targetUrl.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {

        throw new Error(
          data.detail ||
          "Web scan failed"
        );
      }

      setScanResult(data);

    } catch (err) {

      setError(
        err.message ||
        "Web scan failed"
      );

    } finally {

      setLoading(false);
    }
  }


  /* =========================================================
     API SECURITY SCAN
     ========================================================= */

  async function runApiScan() {

    setError("");
    setApiScanResult(null);

    if (!apiUrl.trim()) {

      setError(
        "Please enter an API target URL."
      );

      return;
    }

    setApiLoading(true);

    try {

      const response = await fetch(
        `${API_BASE}/api-security/scan`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${token}`,
          },

          body: JSON.stringify({
            url: apiUrl.trim(),

            openapi_url:
              openapiUrl.trim() ||
              null,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {

        throw new Error(
          data.detail ||
          "API scan failed"
        );
      }

      setApiScanResult(data);

    } catch (err) {

      setError(
        err.message ||
        "API scan failed"
      );

    } finally {

      setApiLoading(false);
    }
  }


  /* =========================================================
     SECURITY OPERATIONS
     ========================================================= */

  async function loadSecurityOperations() {

    setOperationsLoading(true);
    setError("");

    try {

      const headers = {
        Authorization:
          `Bearer ${token}`,
      };

      const [eventsResponse, incidentsResponse] =
        await Promise.all([
          fetch(
            `${API_BASE}/security-operations/events`,
            {
              headers,
            }
          ),

          fetch(
            `${API_BASE}/security-operations/incidents`,
            {
              headers,
            }
          ),
        ]);

      const eventsData =
        await eventsResponse.json();

      const incidentsData =
        await incidentsResponse.json();

      if (!eventsResponse.ok) {

        throw new Error(
          eventsData.detail ||
          "Unable to load security events"
        );
      }

      if (!incidentsResponse.ok) {

        throw new Error(
          incidentsData.detail ||
          "Unable to load incidents"
        );
      }

      setEvents(
        eventsData.events || []
      );

      setIncidents(
        incidentsData.incidents || []
      );

    } catch (err) {

      setError(
        err.message ||
        "Unable to load Security Operations"
      );

    } finally {

      setOperationsLoading(false);
    }
  }


  async function createSecurityEvent() {
    setEventLoading(true);
    setError("");
    setOperationsMessage("");

    if (!eventType.trim() || !eventMessage.trim()) {
      setError("Event type and message are required.");
      setEventLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/security-operations/events`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          event_type: eventType.trim(),
          severity: eventSeverity,
          message: eventMessage.trim(),
          source: eventSource.trim() || null,
          source_ip: eventSourceIp.trim() || null,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to create security event");
      }

      setOperationsMessage(`Security event #${data.event_id} created successfully.`);
      setEventType("");
      setEventSeverity("medium");
      setEventMessage("");
      setEventSource("");
      setEventSourceIp("");
      await loadSecurityOperations();
    } catch (err) {
      setError(err.message || "Unable to create security event");
    } finally {
      setEventLoading(false);
    }
  }


  async function createIncident() {
    setIncidentLoading(true);
    setError("");
    setOperationsMessage("");

    if (!incidentTitle.trim()) {
      setError("Incident title is required.");
      setIncidentLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/security-operations/incidents`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          title: incidentTitle.trim(),
          severity: incidentSeverity,
          description: incidentDescription.trim() || null,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to create incident");
      }

      setOperationsMessage(`Incident #${data.incident_id} created successfully.`);
      setIncidentTitle("");
      setIncidentSeverity("medium");
      setIncidentDescription("");
      await loadSecurityOperations();
    } catch (err) {
      setError(err.message || "Unable to create incident");
    } finally {
      setIncidentLoading(false);
    }
  }

  async function submitInvestigation() {
    if (!selectedIncidentId || !investigationFindings.trim()) {
      setError("Select an incident and enter investigation findings.");
      return;
    }

    setIncidentActionLoading(true);
    setError("");
    setOperationsMessage("");

    try {
      const response = await fetch(
        `${API_BASE}/security-operations/incidents/${selectedIncidentId}/investigation`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ findings: investigationFindings.trim() }),
        }
      );

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to save investigation findings.");
      }

      setOperationsMessage("Investigation findings saved successfully.");
      setInvestigationFindings("");
      await loadSecurityOperations();
    } catch (err) {
      setError(err.message || "Unable to save investigation findings.");
    } finally {
      setIncidentActionLoading(false);
    }
  }

  async function submitResponseAction() {
    if (!selectedIncidentId || !responseAction.trim()) {
      setError("Select an incident and enter a response action.");
      return;
    }

    setIncidentActionLoading(true);
    setError("");
    setOperationsMessage("");

    try {
      const response = await fetch(
        `${API_BASE}/security-operations/incidents/${selectedIncidentId}/response`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ response_action: responseAction.trim() }),
        }
      );

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to save response action.");
      }

      setOperationsMessage("Response action recorded successfully.");
      setResponseAction("");
      await loadSecurityOperations();
    } catch (err) {
      setError(err.message || "Unable to save response action.");
    } finally {
      setIncidentActionLoading(false);
    }
  }


  /* =========================================================
     LOGOUT
     ========================================================= */

  function logout() {

    setToken("");

    setLoggedIn(false);

    setUsername("");
    setPassword("");

    setPage("dashboard");

    setScanResult(null);
    setApiScanResult(null);

    setEvents([]);
    setIncidents([]);

    setError("");
    setOperationsMessage("");
  }


  /* =========================================================
     WEB FINDINGS
     ========================================================= */

  function getWebFindings() {

    return (
      scanResult?.results?.findings ||
      []
    );
  }


  function getWebStatusCounts() {

    const findings =
      getWebFindings();

    return {
      total: findings.length,

      pass:
        findings.filter(
          (finding) =>
            finding.status === "pass"
        ).length,

      fail:
        findings.filter(
          (finding) =>
            finding.status === "fail"
        ).length,

      review:
        findings.filter(
          (finding) =>
            finding.status === "review"
        ).length,

      notTested:
        findings.filter(
          (finding) =>
            finding.status === "not_tested"
        ).length,
    };
  }


  /* =========================================================
     API FINDINGS
     ========================================================= */

  function getApiFindings() {

    return (
      apiScanResult?.results?.findings ||
      []
    );
  }


  function getApiFinding(id) {

    const findings =
      getApiFindings();

    const exactFinding =
      findings.find(
        (finding) =>
          finding.id === id
      );

    if (exactFinding) {
      return exactFinding;
    }


    if (id === "API8") {

      const api8Findings =
        findings.filter(
          (finding) =>
            String(
              finding.id || ""
            ).startsWith("API8-")
        );

      if (api8Findings.length === 0) {
        return null;
      }

      let combinedStatus = "pass";

      if (
        api8Findings.some(
          (finding) =>
            finding.status === "fail"
        )
      ) {

        combinedStatus = "fail";

      } else if (
        api8Findings.some(
          (finding) =>
            finding.status === "review"
        )
      ) {

        combinedStatus = "review";
      }


      const highestSeverity =
        api8Findings.some(
          (finding) =>
            finding.severity === "high"
        )
          ? "high"
          : api8Findings.some(
              (finding) =>
                finding.severity === "medium"
            )
          ? "medium"
          : api8Findings.some(
              (finding) =>
                finding.severity === "low"
            )
          ? "low"
          : "info";


      return {
        id: "API8",

        check:
          "Security Misconfiguration",

        status:
          combinedStatus,

        severity:
          highestSeverity,

        description:
          api8Findings
            .map(
              (finding) =>
                finding.description
            )
            .join(" "),

        recommendation:
          api8Findings
            .map(
              (finding) =>
                finding.recommendation
            )
            .join(" "),
      };
    }


    return null;
  }


  function getApiStatus(id) {

    const finding =
      getApiFinding(id);

    if (!finding) {

      return "NOT TESTED";
    }

    return (
      finding.status ||
      "NOT TESTED"
    ).toUpperCase();
  }


  function getStatusClass(status) {

    const value =
      String(status || "")
        .toLowerCase();

    if (value === "pass") {
      return "status-pass";
    }

    if (value === "fail") {
      return "status-fail";
    }

    if (value === "review") {
      return "status-review";
    }

    return "status-info";
  }


  /* =========================================================
     LOGIN PAGE
     ========================================================= */

  if (!loggedIn) {

    return (
      <div className="app">

        <div className="scanlines"></div>

        <header className="topbar">

          <div className="brand">
            CERBERUS
          </div>

          <div className="brand-subtitle">
            CYBERSECURITY ASSESSMENT & RESPONSE PLATFORM
          </div>

        </header>


        <main className="login-page">

          <div className="login-panel">

            <div className="login-eyebrow">
              SECURE ACCESS
            </div>

            <h1>
              CERBERUS
            </h1>

            <p>
              Cybersecurity Assessment & Response Platform
            </p>


            <div className="login-form">

              <input
                type="text"
                placeholder="USERNAME"
                value={username}
                onChange={(e) =>
                  setUsername(
                    e.target.value
                  )
                }
              />


              <input
                type="password"
                placeholder="PASSWORD"
                value={password}
                onChange={(e) =>
                  setPassword(
                    e.target.value
                  )
                }
              />


              <button
                onClick={login}
                disabled={loginLoading}
              >
                {loginLoading
                  ? "AUTHENTICATING..."
                  : "ENTER CERBERUS"}
              </button>

            </div>


            {error && (
              <div className="error-box">
                {error}
              </div>
            )}

          </div>

        </main>

      </div>
    );
  }


  /* =========================================================
     HEAD 01 — WEB APPLICATION SECURITY
     ========================================================= */

  if (page === "web-security") {

    const webFindings =
      getWebFindings();

    const webCounts =
      getWebStatusCounts();


    return (
      <div className="app">

        <div className="scanlines"></div>

        <header className="topbar">

          <div className="brand">
            CERBERUS
          </div>

          <div className="topbar-actions">

            <button
              onClick={() =>
                setPage("dashboard")
              }
            >
              DASHBOARD
            </button>

            <button
              onClick={logout}
            >
              LOGOUT
            </button>

          </div>

        </header>


        <main className="module-page">

          <div className="module-header">

            <div>

              <div className="module-number">
                HEAD 01
              </div>

              <h1>
                WEB APPLICATION SECURITY
              </h1>

              <p>
                OWASP TOP 10 SECURITY ASSESSMENT
              </p>

            </div>

          </div>


          {/* SCANNER */}

          <div className="scanner-panel">

            <label>
              TARGET URL
            </label>

            <input
              type="text"
              value={targetUrl}
              onChange={(e) =>
                setTargetUrl(
                  e.target.value
                )
              }
              placeholder="https://example.com"
            />

            <button
              onClick={runWebScan}
              disabled={loading}
            >
              {loading
                ? "SCANNING..."
                : "RUN WEB SECURITY SCAN"}
            </button>

          </div>


          {error && (
            <div className="error-box">
              {error}
            </div>
          )}


          {/* WEB SECURITY RESULTS */}

          {scanResult && (

            <div className="results-panel">

              <div className="results-title">
                WEB SECURITY RESULTS
              </div>


              {/* SUMMARY */}

              <div className="api-summary">

                <div className="api-summary-title">
                  SCAN SUMMARY
                </div>


                <div className="api-summary-grid">

                  <div>
                    <strong>
                      {webCounts.total}
                    </strong>

                    <span>
                      FINDINGS
                    </span>
                  </div>


                  <div>
                    <strong>
                      {webCounts.pass}
                    </strong>

                    <span>
                      PASS
                    </span>
                  </div>


                  <div>
                    <strong>
                      {webCounts.fail}
                    </strong>

                    <span>
                      FAIL
                    </span>
                  </div>


                  <div>
                    <strong>
                      {webCounts.review}
                    </strong>

                    <span>
                      REVIEW
                    </span>
                  </div>


                  <div>
                    <strong>
                      {webCounts.notTested}
                    </strong>

                    <span>
                      NOT TESTED
                    </span>
                  </div>

                </div>

              </div>


              {/* TARGET INFORMATION */}

              <div className="feed-item">

                <span>
                  TARGET
                </span>

                <strong>
                  {scanResult.results?.target ||
                    targetUrl}
                </strong>

              </div>


              {/* FINDINGS */}

              <div className="api-results">

                <div className="api-results-header">

                  <div>

                    <div className="module-number">
                      OWASP COVERAGE
                    </div>

                    <h2>
                      WEB APPLICATION SECURITY FINDINGS
                    </h2>

                  </div>

                  <div className="api-version">
                    OWASP TOP 10
                  </div>

                </div>


                <div className="api-top10-grid">

                  {webFindings.map(
                    (finding, index) => {

                      const status =
                        String(
                          finding.status ||
                          "not_tested"
                        ).toUpperCase();


                      return (
                        <div
                          className="api-top10-card"
                          key={
                            finding.id ||
                            `web-finding-${index}`
                          }
                        >

                          <div className="api-card-top">

                            <span className="api-id">
                              {finding.id ||
                                `FINDING-${index + 1}`}
                            </span>


                            <span
                              className={
                                `api-status ${
                                  getStatusClass(
                                    finding.status
                                  )
                                }`
                              }
                            >
                              {status}
                            </span>

                          </div>


                          <h3>
                            {finding.category ||
                              "Security Finding"}
                          </h3>


                          <div className="api-severity">

                            SEVERITY:{" "}

                            {String(
                              finding.severity ||
                              "info"
                            ).toUpperCase()}

                          </div>


                          {finding.check && (

                            <p className="api-description">

                              <strong>
                                CHECK:
                              </strong>{" "}

                              {finding.check}

                            </p>

                          )}


                          {finding.description && (

                            <p className="api-description">
                              {finding.description}
                            </p>

                          )}


                          {finding.evidence && (

                            <div className="api-description">

                              <strong>
                                EVIDENCE
                              </strong>

                              <pre>
                                {JSON.stringify(
                                  finding.evidence,
                                  null,
                                  2
                                )}
                              </pre>

                            </div>

                          )}


                          {finding.recommendation && (

                            <p className="api-description">

                              <strong>
                                RECOMMENDATION:
                              </strong>{" "}

                              {finding.recommendation}

                            </p>

                          )}

                        </div>
                      );

                    }
                  )}

                </div>

              </div>


              {/* SCANNER NOTE */}

              <div className="api-summary">

                <div className="api-summary-title">
                  CERBERUS ASSESSMENT NOTE
                </div>

                <p className="api-note">

                  Automated checks identify observable
                  security indicators. Findings marked
                  REVIEW or NOT TESTED may require
                  authenticated, application-specific,
                  or manual security testing.

                </p>

              </div>

            </div>

          )}

        </main>

      </div>
    );
  }


  /* =========================================================
   HEAD 02 — API SECURITY
   ========================================================= */

if (page === "api-security") {
  const mainFindings = OWASP_API_TOP_10.map((item) => ({
    ...item,
    finding: getApiFinding(item.id),
  }));

  const findings = getApiFindings();

  // Five visible demo PASS cards
  const demoPassCards = [
    {
      id: "DEMO-PASS-1",
      name: "API Scan Execution",
      description: "Demonstration PASS: scan result processing completed.",
    },
    {
      id: "DEMO-PASS-2",
      name: "OWASP Category Display",
      description: "Demonstration PASS: OWASP category display is available.",
    },
    {
      id: "DEMO-PASS-3",
      name: "Finding Structure",
      description: "Demonstration PASS: structured finding information is available.",
    },
    {
      id: "DEMO-PASS-4",
      name: "Recommendation Display",
      description: "Demonstration PASS: recommendation display is available.",
    },
    {
      id: "DEMO-PASS-5",
      name: "Scan Summary Display",
      description: "Demonstration PASS: scan summary display is available.",
    },
  ];

  return (
    <div className="app">
      <div className="scanlines"></div>

      <header className="topbar">
        <div className="brand">CERBERUS</div>

        <div className="topbar-actions">
          <button onClick={() => setPage("dashboard")}>
            DASHBOARD
          </button>

          <button onClick={logout}>
            LOGOUT
          </button>
        </div>
      </header>

      <main className="module-page">
        <div className="module-header">
          <div>
            <div className="module-number">HEAD 02</div>
            <h1>API SECURITY</h1>
            <p>OWASP API SECURITY TOP 10 · 2023</p>
          </div>
        </div>

        <div className="scanner-panel">
          <label>API TARGET URL</label>

          <input
            type="text"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            placeholder="https://api.example.com"
          />

          <label>OPENAPI / SWAGGER URL</label>

          <input
            type="text"
            value={openapiUrl}
            onChange={(e) => setOpenapiUrl(e.target.value)}
            placeholder="https://api.example.com/openapi.json"
          />

          <button onClick={runApiScan} disabled={apiLoading}>
            {apiLoading ? "SCANNING API..." : "RUN API SECURITY SCAN"}
          </button>
        </div>

        {error && <div className="error-box">{error}</div>}

        <div className="api-results">
          <div className="api-results-header">
            <div>
              <div className="module-number">OWASP COVERAGE</div>
              <h2>API SECURITY TOP 10</h2>
            </div>

            <div className="api-version">2023</div>
          </div>

          <div className="api-top10-grid">
            {mainFindings.map((item) => {
              const status = getApiStatus(item.id);
              const finding = item.finding;

              return (
                <div className="api-top10-card" key={item.id}>
                  <div className="api-card-top">
                    <span className="api-id">{item.id}</span>

                    <span
                      className={`api-status ${getStatusClass(
                        finding?.status
                      )}`}
                    >
                      {status}
                    </span>
                  </div>

                  <h3>{item.name}</h3>

                  {finding ? (
                    <>
                      <div className="api-severity">
                        SEVERITY:{" "}
                        {String(finding.severity || "INFO").toUpperCase()}
                      </div>

                      <p className="api-description">
                        {finding.description}
                      </p>
                    </>
                  ) : (
                    <p className="api-description">
                      Run an API security scan to evaluate this OWASP category.
                    </p>
                  )}
                </div>
              );
            })}
          </div>

          {/* Five additional presentation demo cards */}
          {apiScanResult && (
            <>
              <div className="api-results-header" style={{ marginTop: "28px" }}>
                <div>
                  <div className="module-number">DEMONSTRATION</div>
                  <h2>ADDITIONAL PASS CHECKS</h2>
                </div>
              </div>

              <div className="api-top10-grid">
                {demoPassCards.map((item) => (
                  <div className="api-top10-card" key={item.id}>
                    <div className="api-card-top">
                      <span className="api-id">{item.id}</span>

                      <span className="api-status status-pass">
                        PASS
                      </span>
                    </div>

                    <h3>{item.name}</h3>

                    <div className="api-severity">
                      SEVERITY: INFO
                    </div>

                    <p className="api-description">
                      {item.description}
                    </p>
                  </div>
                ))}
              </div>
            </>
          )}

          {apiScanResult && (
            <div className="api-summary">
              <div className="api-summary-title">SCAN SUMMARY</div>

              <div className="api-summary-grid">
                <div>
                  <strong>{findings.length + demoPassCards.length}</strong>
                  <span>FINDINGS</span>
                </div>

                <div>
                  <strong>
                    {findings.filter(
                      (item) => item.status === "pass"
                    ).length + demoPassCards.length}
                  </strong>
                  <span>PASS</span>
                </div>

                <div>
                  <strong>
                    {findings.filter(
                      (item) => item.status === "fail"
                    ).length}
                  </strong>
                  <span>FAIL</span>
                </div>

                <div>
                  <strong>
                    {findings.filter(
                      (item) => item.status === "review"
                    ).length}
                  </strong>
                  <span>REVIEW</span>
                </div>
              </div>

              <p className="api-note">
                The five additional PASS cards are presentation-only
                demonstration entries. They do not confirm that the target
                API is secure.
              </p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

/* ========================================================= 
     HEAD 03 — SECURITY OPERATIONS
     ========================================================= */

  if (page === "security-operations") {

    const openIncidents =
      incidents.filter(
        (incident) =>
          incident.status === "open"
      );

    const highEvents =
      events.filter(
        (event) =>
          event.severity === "high" ||
          event.severity === "critical"
      );


    return (
      <div className="app">

        <div className="scanlines"></div>

        <header className="topbar">

          <div className="brand">
            CERBERUS
          </div>

          <div className="topbar-actions">

            <button
              onClick={() =>
                setPage("dashboard")
              }
            >
              DASHBOARD
            </button>

            <button
              onClick={logout}
            >
              LOGOUT
            </button>

          </div>

        </header>


        <main className="module-page">

          <div className="module-header">

            <div>

              <div className="module-number">
                HEAD 03
              </div>

              <h1>
                SECURITY OPERATIONS
              </h1>

              <p>
                DETECT · INVESTIGATE · RESPOND
              </p>

            </div>

          </div>


          <button
            className="armed-button"
            onClick={loadSecurityOperations}
            disabled={operationsLoading}
          >
            {operationsLoading
              ? "LOADING OPERATIONS..."
              : "REFRESH SECURITY OPERATIONS"}
          </button>


          {error && (
            <div className="error-box">
              {error}
            </div>
          )}


          {operationsMessage && (
            <div className="feed-item">
              <span>
                CERBERUS
              </span>

              <strong>
                {operationsMessage}
              </strong>
            </div>
          )}


          {/* SECURITY METRICS */}

          <div className="dashboard-grid">

            <div className="dashboard-panel">

              <div className="panel-title">
                DETECTION
              </div>

              <div className="feed-item">

                <span>
                  EVENTS
                </span>

                <strong>
                  {events.length} TOTAL
                </strong>

              </div>

              <div className="feed-item">

                <span>
                  HIGH / CRITICAL
                </span>

                <strong>
                  {highEvents.length}
                </strong>

              </div>

            </div>


            <div className="dashboard-panel">

              <div className="panel-title">
                INCIDENT RESPONSE
              </div>

              <div className="feed-item">

                <span>
                  INCIDENTS
                </span>

                <strong>
                  {incidents.length} TOTAL
                </strong>

              </div>

              <div className="feed-item">

                <span>
                  OPEN
                </span>

                <strong>
                  {openIncidents.length}
                </strong>

              </div>

            </div>

          </div>


          {/* CREATE EVENT */}

          <div className="scanner-panel">

            <div className="panel-title">
              CREATE SECURITY EVENT
            </div>

            <label>
              EVENT TYPE
            </label>

            <input
              type="text"
              value={eventType}
              onChange={(e) =>
                setEventType(
                  e.target.value
                )
              }
              placeholder="Failed Login"
            />


            <label>
              SEVERITY
            </label>

            <select
              value={eventSeverity}
              onChange={(e) =>
                setEventSeverity(
                  e.target.value
                )
              }
            >
              <option value="low">
                LOW
              </option>

              <option value="medium">
                MEDIUM
              </option>

              <option value="high">
                HIGH
              </option>

              <option value="critical">
                CRITICAL
              </option>
            </select>


            <label>
              MESSAGE
            </label>

            <input
              type="text"
              value={eventMessage}
              onChange={(e) =>
                setEventMessage(
                  e.target.value
                )
              }
              placeholder="Describe the security event"
            />


            <label>
              SOURCE
            </label>

            <input
              type="text"
              value={eventSource}
              onChange={(e) =>
                setEventSource(
                  e.target.value
                )
              }
              placeholder="Authentication System"
            />


            <label>
              SOURCE IP
            </label>

            <input
              type="text"
              value={eventSourceIp}
              onChange={(e) =>
                setEventSourceIp(
                  e.target.value
                )
              }
              placeholder="192.168.1.100"
            />


            <button
              onClick={createSecurityEvent}
              disabled={eventLoading}
            >
              {eventLoading
                ? "CREATING EVENT..."
                : "CREATE SECURITY EVENT"}
            </button>

          </div>


          {/* CREATE INCIDENT */}

          <div className="scanner-panel">

            <div className="panel-title">
              CREATE INCIDENT
            </div>

            <label>
              INCIDENT TITLE
            </label>

            <input
              type="text"
              value={incidentTitle}
              onChange={(e) =>
                setIncidentTitle(
                  e.target.value
                )
              }
              placeholder="Suspicious Login Activity"
            />


            <label>
              SEVERITY
            </label>

            <select
              value={incidentSeverity}
              onChange={(e) =>
                setIncidentSeverity(
                  e.target.value
                )
              }
            >
              <option value="low">
                LOW
              </option>

              <option value="medium">
                MEDIUM
              </option>

              <option value="high">
                HIGH
              </option>

              <option value="critical">
                CRITICAL
              </option>
            </select>


            <label>
              DESCRIPTION
            </label>

            <input
              type="text"
              value={incidentDescription}
              onChange={(e) =>
                setIncidentDescription(
                  e.target.value
                )
              }
              placeholder="Describe the incident"
            />


            <button
              onClick={createIncident}
              disabled={incidentLoading}
            >
              {incidentLoading
                ? "CREATING INCIDENT..."
                : "CREATE INCIDENT"}
            </button>

          </div>


          {/* EVENTS */}

          <div className="results-panel">

            <div className="results-title">
              SECURITY EVENTS
            </div>

            {events.length === 0 ? (

              <p className="api-note">
                No security events loaded.
                Click REFRESH SECURITY OPERATIONS.
              </p>

            ) : (

              events.map(
                (event) => (

                  <div
                    className="feed-item"
                    key={event.id}
                  >

                    <span>
                      {String(
                        event.severity ||
                        "INFO"
                      ).toUpperCase()}
                    </span>

                    <strong>
                      {event.event_type}
                      {" — "}
                      {event.message}
                    </strong>

                  </div>

                )
              )

            )}

          </div>


          {/* INCIDENTS */}
          <div className="results-panel">
            <div className="results-title">INCIDENTS</div>

            {incidents.length === 0 ? (
              <p className="api-note">
                No incidents loaded. Create an incident above.
              </p>
            ) : (
              incidents.map((incident) => (
                <div
                  className="feed-item"
                  key={incident.id}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "stretch",
                    gap: "10px",
                    padding: "16px",
                    marginBottom: "12px",
                  }}
                >
                  <span>
                    {String(incident.severity || "INFO").toUpperCase()}
                  </span>
                  <strong>
                    {incident.title} — {String(incident.status || "OPEN").toUpperCase()}
                  </strong>
                  <p>
                    <strong>Description / investigation history:</strong>{" "}
                    {incident.description || "No investigation details recorded."}
                  </p>
                  <p>
                    <strong>Assigned to:</strong> {incident.assigned_to || "Unassigned"}
                  </p>
                  <p>
                    <strong>Response actions:</strong>{" "}
                    {incident.response_action || "No response actions recorded."}
                  </p>

                  <button
                    type="button"
                    onClick={() => {
                      setSelectedIncidentId(incident.id);
                      setError("");
                      setOperationsMessage("");
                    }}
                  >
                    {selectedIncidentId === incident.id
                      ? "SELECTED INCIDENT"
                      : "INVESTIGATE / RESPOND"}
                  </button>

                  {selectedIncidentId === incident.id && (
                    <div style={{ display: "grid", gap: "10px" }}>
                      <label>
                        INVESTIGATION FINDINGS
                        <textarea
                          value={investigationFindings}
                          onChange={(event) => setInvestigationFindings(event.target.value)}
                          placeholder="Record what you reviewed and what you discovered..."
                          rows={3}
                          style={{ display: "block", width: "100%", marginTop: "6px" }}
                        />
                      </label>
                      <button
                        type="button"
                        onClick={submitInvestigation}
                        disabled={incidentActionLoading}
                      >
                        {incidentActionLoading ? "SAVING..." : "SAVE INVESTIGATION"}
                      </button>

                      <label>
                        RESPONSE ACTION
                        <textarea
                          value={responseAction}
                          onChange={(event) => setResponseAction(event.target.value)}
                          placeholder="Record containment, remediation, or monitoring actions..."
                          rows={3}
                          style={{ display: "block", width: "100%", marginTop: "6px" }}
                        />
                      </label>
                      <button
                        type="button"
                        onClick={submitResponseAction}
                        disabled={incidentActionLoading}
                      >
                        {incidentActionLoading ? "SAVING..." : "SAVE RESPONSE ACTION"}
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

        </main>

      </div>
    );
  }


  /* =========================================================
     MAIN DASHBOARD
     ========================================================= */

  return (
    <div className="app">

      <div className="scanlines"></div>

      <header className="topbar">

        <div>

          <div className="brand">
            CERBERUS
          </div>

          <div className="brand-subtitle">
            CYBERSECURITY ASSESSMENT & RESPONSE PLATFORM
          </div>

        </div>


        <div className="topbar-actions">

          <span className="user-display">
            {username}
          </span>

          <button
            onClick={logout}
          >
            LOGOUT
          </button>

        </div>

      </header>


      <main className="dashboard">


        {/* HERO */}

        <section className="hero">

          <div className="hero-text">

            <div className="module-number">
              SECURITY CONTROL CENTER
            </div>

            <h1>
              CERBERUS
            </h1>

            <p>
              ASSESS · DETECT · INVESTIGATE · RESPOND
            </p>

            <button
              className="armed-button"
            >
              CERBERUS ARMED
            </button>

          </div>


          {/* CERBERUS HERO IMAGE */}

          <div className="cerberus-visual">

            <div className="cerberus-hud-ring"></div>

            <img
              src="/cerberus-hero.png"
              alt="CERBERUS three-headed security guardian"
              className="cerberus-hero-image"
            />

            <div className="cerberus-visual-label">
              THREAT ENGINE ONLINE
            </div>

          </div>

        </section>


        {/* THREE HEADS */}

        <section className="heads-grid">


          <div className="head-card">

            <div className="head-number">
              01
            </div>

            <h2>
              WEB APPLICATION SECURITY
            </h2>

            <p>
              OWASP TOP 10
            </p>

            <button
              onClick={() =>
                setPage(
                  "web-security"
                )
              }
            >
              OPEN MODULE
            </button>

          </div>


          <div className="head-card">

            <div className="head-number">
              02
            </div>

            <h2>
              API SECURITY
            </h2>

            <p>
              OWASP API SECURITY TOP 10
            </p>

            <button
              onClick={() =>
                setPage(
                  "api-security"
                )
              }
            >
              OPEN MODULE
            </button>

          </div>


          <div className="head-card">

            <div className="head-number">
              03
            </div>

            <h2>
              SECURITY OPERATIONS
            </h2>

            <p>
              DETECT · INVESTIGATE · RESPOND
            </p>

            <button
              onClick={() => {

                setPage(
                  "security-operations"
                );

              }}
            >
              OPEN MODULE
            </button>

          </div>

        </section>


        {/* DASHBOARD LOWER SECTION */}

        <section className="dashboard-grid">


          <div className="dashboard-panel">

            <div className="panel-title">
              THREAT MATRIX
            </div>


            <div className="matrix-bars">


              <div className="matrix-row">

                <span>
                  CRITICAL
                </span>

                <div className="bar">

                  <div
                    className="bar-fill"
                    style={{
                      width: "18%"
                    }}
                  ></div>

                </div>

              </div>


              <div className="matrix-row">

                <span>
                  HIGH
                </span>

                <div className="bar">

                  <div
                    className="bar-fill"
                    style={{
                      width: "34%"
                    }}
                  ></div>

                </div>

              </div>


              <div className="matrix-row">

                <span>
                  MEDIUM
                </span>

                <div className="bar">

                  <div
                    className="bar-fill"
                    style={{
                      width: "58%"
                    }}
                  ></div>

                </div>

              </div>


              <div className="matrix-row">

                <span>
                  LOW
                </span>

                <div className="bar">

                  <div
                    className="bar-fill"
                    style={{
                      width: "76%"
                    }}
                  ></div>

                </div>

              </div>

            </div>

          </div>


          <div className="dashboard-panel">

            <div className="panel-title">
              LIVE FEED
            </div>


            <div className="feed-item">

              <span>
                SYSTEM
              </span>

              <strong>
                CERBERUS ONLINE
              </strong>

            </div>


            <div className="feed-item">

              <span>
                HEAD 01
              </span>

              <strong>
                WEB SECURITY READY
              </strong>

            </div>


            <div className="feed-item">

              <span>
                HEAD 02
              </span>

              <strong>
                API SECURITY READY
              </strong>

            </div>


            <div className="feed-item">

              <span>
                HEAD 03
              </span>

              <strong>
                SOC MODULE READY
              </strong>

            </div>

          </div>

        </section>

      </main>

    </div>
  );
}


export default App;