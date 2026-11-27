"use client";

import * as React from "react";
import { AppLayout, TopBar, Button, RiskBadge, RiskDot, ResultCard, Card } from "@/components/cyber";
import { ChevronRight, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import { API_URL } from "@/lib/config";

type RiskLevel = "safe" | "moderate" | "critical";
type ScanType = "Phishing" | "File" | "UPI" | "Network";
type TimeFilter = "today" | "week" | "month";

interface ScanEntry {
  id: string;
  target: string;
  type: ScanType;
  time: string;
  timestamp: number;
  date: string;
  risk: RiskLevel;
  result: {
    title: string;
    flags: string[];
    aiExplanation: string;
    actions: string[];
    rawResult?: Record<string, any>;
  };
}

const riskSeverity = { safe: "None", moderate: "Medium", critical: "Critical" } as const;

export default function ReportsPage() {
  const [scans, setScans] = React.useState<ScanEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState(false);
  const [typeFilter, setTypeFilter] = React.useState<"All" | ScanType>("All");
  const [timeFilter, setTimeFilter] = React.useState<TimeFilter>("month");
  const [expandedId, setExpandedId] = React.useState<string | null>(null);

  const handleExportTextReport = async () => {
    try {
      const token = localStorage.getItem("cyberguard-token") || "";
      const incRes = await fetch(`${API_URL}/api/v1/incidents`, {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (incRes.ok) {
        const incidentsList = await incRes.json();
        if (incidentsList.length > 0) {
          const firstIncidentId = incidentsList[0].id;
          const reportRes = await fetch(`${API_URL}/api/v1/incidents/${firstIncidentId}/text`, {
            headers: { "Authorization": `Bearer ${token}` }
          });
          if (reportRes.ok) {
            const text = await reportRes.text();
            const blob = new Blob([text], { type: "text/plain" });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `incident_report_${firstIncidentId}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
          } else {
            alert("No text report available for the selected incident.");
          }
        } else {
          alert("No active incidents found to export.");
        }
      } else {
        alert("Failed to fetch incidents list.");
      }
    } catch (err) {
      console.error(err);
      alert("Error exporting report.");
    }
  };

  React.useEffect(() => {
    async function loadScans() {
      try {
        const backendUrl = API_URL;
        const token = localStorage.getItem("cyberguard-token") || "";
        const res = await fetch(`${backendUrl}/scan-history`, {
          headers: {
            "Authorization": `Bearer ${token}`
          }
        });
        if (!res.ok) throw new Error();
        const rawList = await res.json();
        
        const formatted: ScanEntry[] = rawList.map((item: any) => {
          let parsedResult: any = {};
          try {
            const cleanJsonStr = item.result
              .replace(/'/g, '"')
              .replace(/None/g, 'null')
              .replace(/True/g, 'true')
              .replace(/False/g, 'false');
            parsedResult = JSON.parse(cleanJsonStr);
          } catch(e) {
            parsedResult = { summary: item.result };
          }
          
          let risk: RiskLevel = "safe";
          const severity = (parsedResult.severity || "None").toLowerCase();
          if (severity === "critical" || severity === "high" || item.result.includes("PHISHING") || item.result.includes("INFECTED")) {
            risk = "critical";
          } else if (severity === "medium" || item.result.includes("SUSPICIOUS")) {
            risk = "moderate";
          }
          
          let scanType: ScanType = "Phishing";
          if (item.scan_type.includes("File")) scanType = "File";
          else if (item.scan_type.includes("Network")) scanType = "Network";
          else if (item.scan_type.includes("UPI")) scanType = "UPI";

          const timestamp = Date.parse(item.timestamp);
          const date = Number.isFinite(timestamp) ? new Date(timestamp) : null;
          
          return {
            id: String(item.id),
            target: item.target,
            type: scanType,
            timestamp,
            time: date?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) ?? "Unknown time",
            date: date?.toLocaleDateString() ?? "Unknown date",
            risk,
            result: {
              title: parsedResult.title || parsedResult.summary || "Scan Completed",
              flags: parsedResult.flags || (parsedResult.malicious_engines ? [`${parsedResult.malicious_engines} malicious flags`] : ["Completed scan successfully"]),
              aiExplanation: parsedResult.summary || parsedResult.aiExplanation || "No scan explanation is available.",
              actions: parsedResult.actions || ["No critical actions required."],
              rawResult: parsedResult
            }
          };
        });
        setScans(formatted);
      } catch (err) {
        console.warn("Could not load scan history", err);
        setLoadError(true);
      } finally {
        setLoading(false);
      }
    }
    loadScans();
  }, []);

  const cutoff = new Date();
  if (timeFilter === "today") cutoff.setHours(0, 0, 0, 0);
  else cutoff.setDate(cutoff.getDate() - (timeFilter === "week" ? 7 : 30));
  const filtered = scans.filter((scan) =>
    (typeFilter === "All" || scan.type === typeFilter) && scan.timestamp >= cutoff.getTime()
  );

  // Group by date
  const grouped = filtered.reduce<Record<string, ScanEntry[]>>((acc, scan) => {
    if (!acc[scan.date]) acc[scan.date] = [];
    acc[scan.date].push(scan);
    return acc;
  }, {});

  const typeFilters: ("All" | ScanType)[] = ["All", "Phishing", "File", "UPI", "Network"];
  const timeFilters: { label: string; value: TimeFilter }[] = [
    { label: "Today", value: "today" },
    { label: "Week", value: "week" },
    { label: "Month", value: "month" },
  ];

  return (
    <AppLayout waveIntensity="minimal">
      <div className="mx-auto max-w-[860px]">
        <TopBar title="Scan History" subtitle="All your past security checks" />

        {/* Filters */}
        <Card className="mb-6 flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-2">
            {typeFilters.map((f) => (
              <button
                key={f}
                onClick={() => setTypeFilter(f)}
                className={cn(
                  "rounded-full border px-3 py-1.5 text-xs font-medium transition-all",
                  typeFilter === f
                    ? "border-primary bg-primary-dim text-primary"
                    : "border-primary-border bg-transparent text-text-secondary hover:bg-primary-dim"
                )}
              >
                {f}
              </button>
            ))}
            <span className="mx-1 self-center text-text-muted">·</span>
            {timeFilters.map((f) => (
              <button
                key={f.value}
                onClick={() => setTimeFilter(f.value)}
                className={cn(
                  "rounded-full border px-3 py-1.5 text-xs font-medium transition-all",
                  timeFilter === f.value
                    ? "border-primary bg-primary-dim text-primary"
                    : "border-primary-border bg-transparent text-text-secondary hover:bg-primary-dim"
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
          <Button variant="ghost" size="sm" onClick={handleExportTextReport}>Export Text Report</Button>
        </Card>

        {/* Results */}
        {loading ? (
          <p role="status" className="py-16 text-center text-text-secondary">Loading scan history…</p>
        ) : loadError ? (
          <p role="alert" className="py-16 text-center text-text-secondary">Scan history could not be loaded.</p>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center py-16 text-center">
            <p className="font-display text-lg font-semibold text-text-primary">{scans.length > 0 ? "No scans match these filters." : "No scans yet."}</p>
            <p className="mt-2 text-sm text-text-secondary">Head to a tool to run your first check.</p>
            <Link href="/phishing" className="mt-6">
              <Button>Go to Phishing Checker</Button>
            </Link>
          </div>
        ) : (
          Object.entries(grouped).map(([date, scans]) => (
            <div key={date} className="mb-6">
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                {date}
              </p>
              <div className="border-t border-border" />

              <div className="divide-y divide-border">
                {scans.map((scan) => {
                  const isExpanded = expandedId === scan.id;
                  return (
                    <div key={scan.id}>
                      <button
                        onClick={() => setExpandedId(isExpanded ? null : scan.id)}
                        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-bg-card-hover"
                      >
                        <RiskDot risk={scan.risk} />
                        <span className="flex-1 truncate font-mono text-sm text-text-primary">
                          {scan.target}
                        </span>
                        <span className="hidden text-xs text-text-muted sm:inline">{scan.type}</span>
                        <span className="text-xs text-text-muted">{scan.time}</span>
                        <RiskBadge severity={riskSeverity[scan.risk]} />
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4 text-text-muted" />
                        ) : (
                          <ChevronRight className="h-4 w-4 text-text-muted" />
                        )}
                      </button>

                      {isExpanded && (
                        <div className="border-t border-dashed border-border px-4 pb-4 pt-2">
                          <ResultCard
                            verdict={scan.risk === "critical" ? "DANGEROUS" : scan.risk === "moderate" ? "SUSPICIOUS" : "CLEAN"}
                            severity={riskSeverity[scan.risk]}
                            title={scan.result.title}
                            target={scan.target}
                            aiExplanation={scan.result.aiExplanation}
                            actions={scan.result.actions}
                            onReset={() => setExpandedId(null)}
                            resetLabel="Collapse ▴"
                            rawResult={scan.result.rawResult}
                            mlPrediction={scan.result.rawResult?.ml_prediction}
                          >
                            {scan.result.flags && scan.result.flags.length > 0 && (
                              <div className="mt-3 space-y-1">
                                <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">Indicators</p>
                                <ul className="list-disc pl-4 space-y-0.5 text-xs text-text-secondary font-mono">
                                  {scan.result.flags.map((f: string, idx: number) => <li key={idx}>{f}</li>)}
                                </ul>
                              </div>
                            )}
                          </ResultCard>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        )}
      </div>
    </AppLayout>
  );
}
