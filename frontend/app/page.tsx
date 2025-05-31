"use client"

import { useState, useEffect } from "react"
import {
  Shield,
  Sun,
  Moon,
  Code,
  Globe,
  Search,
  Rocket,
  Download,
  FileText,
  Github,
  ExternalLink,
  AlertTriangle,
  XCircle,
  ChevronDown,
  ChevronRight,
  Info,
  CheckCircle,
  Clock,
  RefreshCw,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Progress } from "@/components/ui/progress"

// OWASP Top 10 categories
const owaspCategories = [
  "A01:2021 – Injection",
  "A02:2021 – Cryptographic Failures", 
  "A03:2021 – Sensitive Data Exposure",
  "A04:2021 – XXE",
  "A05:2021 – Broken Access Control",
  "A06:2021 – Security Misconfiguration",
  "A07:2021 – Cross-Site Scripting",
  "A08:2021 – Insecure Deserialization",
  "A09:2021 – Vulnerable Components",
  "A10:2021 – SSRF"
]

// Programming languages for SAST
const supportedLanguages = [
  { value: "javascript", label: "JavaScript" },
  { value: "python", label: "Python" },
  { value: "java", label: "Java" },
  { value: "php", label: "PHP" },
  { value: "go", label: "Go" },
  { value: "c", label: "C/C++" },
  { value: "csharp", label: "C#" },
  { value: "ruby", label: "Ruby" },
  { value: "typescript", label: "TypeScript" }
]

// Backend API configuration
const API_BASE_URL = "http://localhost:5000"

export default function OwaspEye() {
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [activeTab, setActiveTab] = useState("website")
  
  // DAST states
  const [url, setUrl] = useState("")
  const [timeout, setTimeout] = useState(10)
  const [dastScanResults, setDastScanResults] = useState(null)
  const [isDastScanning, setIsDastScanning] = useState(false)
  const [dastScanStatus, setDastScanStatus] = useState("")
  const [currentDastScanId, setCurrentDastScanId] = useState(null)
  const [dastScanProgress, setDastScanProgress] = useState(0)
  const [dastError, setDastError] = useState("")
  
  // SAST states
  const [code, setCode] = useState("")
  const [selectedLanguage, setSelectedLanguage] = useState("javascript")
  const [sastScanResults, setSastScanResults] = useState(null)
  const [isSastScanning, setIsSastScanning] = useState(false)
  const [sastScanStatus, setSastScanStatus] = useState("")
  const [currentSastScanId, setCurrentSastScanId] = useState(null)
  const [sastScanProgress, setSastScanProgress] = useState(0)
  const [sastError, setSastError] = useState("")
  
  // Common states
  const [severityFilter, setSeverityFilter] = useState("all")
  const [categoryFilter, setCategoryFilter] = useState("all")
  const [sidebarOpen, setSidebarOpen] = useState(false)

  // Get current scan results based on active tab
  const scanResults = activeTab === "website" ? dastScanResults : sastScanResults

  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add("dark")
    } else {
      document.documentElement.classList.remove("dark")
    }
  }, [isDarkMode])

  // Poll DAST scan status when scanning
  useEffect(() => {
    let interval
    if (isDastScanning && currentDastScanId) {
      interval = setInterval(async () => {
        try {
          const response = await fetch(`${API_BASE_URL}/scan/${currentDastScanId}/status`)
          const data = await response.json()
          
          if (data.status === 'completed') {
            const resultResponse = await fetch(`${API_BASE_URL}/scan/${currentDastScanId}/result`)
            const resultData = await resultResponse.json()
            
            setDastScanResults(resultData)
            setIsDastScanning(false)
            setDastScanStatus("Scan completed")
            setDastScanProgress(100)
            setCurrentDastScanId(null)
          } else if (data.status === 'failed') {
            setDastError("DAST scan failed. Please try again.")
            setIsDastScanning(false)
            setCurrentDastScanId(null)
          } else {
            setDastScanStatus(data.current_step || "Scanning...")
            const steps = [
              "Initializing",
              "Verifying target accessibility", 
              "Scanning for Injection Flaws",
              "Scanning for Authentication Issues",
              "Scanning for Sensitive Data Exposure",
              "Scanning for XXE Vulnerabilities",
              "Scanning for Access Control Issues",
              "Scanning for Security Misconfiguration",
              "Scanning for XSS Vulnerabilities",
              "Scanning for Deserialization Issues",
              "Scanning for Vulnerable Components",
              "Scanning for SSRF and Monitoring Issues",
              "Scan completed"
            ]
            const currentIndex = steps.indexOf(data.current_step)
            setDastScanProgress(currentIndex >= 0 ? ((currentIndex + 1) / steps.length) * 100 : 20)
          }
        } catch (err) {
          console.error("Error polling DAST scan status:", err)
        }
      }, 2000)
    }
    
    return () => {
      if (interval) clearInterval(interval)
    }
  }, [isDastScanning, currentDastScanId])

  // Poll SAST scan status when scanning
  useEffect(() => {
    let interval
    if (isSastScanning && currentSastScanId) {
      interval = setInterval(async () => {
        try {
          const response = await fetch(`${API_BASE_URL}/sast/scan/${currentSastScanId}/status`)
          const data = await response.json()
          
          if (data.status === 'completed') {
            const resultResponse = await fetch(`${API_BASE_URL}/sast/scan/${currentSastScanId}/result`)
            const resultData = await resultResponse.json()
            
            setSastScanResults(resultData)
            setIsSastScanning(false)
            setSastScanStatus("Scan completed")
            setSastScanProgress(100)
            setCurrentSastScanId(null)
          } else if (data.status === 'failed') {
            setSastError("SAST scan failed. Please try again.")
            setIsSastScanning(false)
            setCurrentSastScanId(null)
          } else {
            setSastScanStatus(data.current_step || "Analyzing code...")
            // Estimate progress based on vulnerabilities found and elapsed time
            const startTime = new Date(data.start_time)
            const elapsed = (Date.now() - startTime.getTime()) / 1000
            const estimatedProgress = Math.min((elapsed / 30) * 100, 90) // Assume 30s average scan time
            setSastScanProgress(estimatedProgress)
          }
        } catch (err) {
          console.error("Error polling SAST scan status:", err)
        }
      }, 2000)
    }
    
    return () => {
      if (interval) clearInterval(interval)
    }
  }, [isSastScanning, currentSastScanId])

  const handleScanWebsite = async () => {
    if (!url.trim()) {
      setDastError("Please enter a valid URL")
      return
    }

    setDastError("")
    setIsDastScanning(true)
    setDastScanResults(null)
    setDastScanStatus("Initializing scan...")
    setDastScanProgress(0)

    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url.trim(),
          timeout: timeout
        })
      })

      const data = await response.json()

      if (response.ok) {
        setCurrentDastScanId(data.scan_id)
        setDastScanStatus("Scan started successfully")
      } else {
        setDastError(data.error || "Failed to start scan")
        setIsDastScanning(false)
      }
    } catch (err) {
      setDastError("Failed to connect to backend. Make sure the server is running on port 5000.")
      setIsDastScanning(false)
    }
  }

  const handleScanCode = async () => {
    if (!code.trim()) {
      setSastError("Please enter some code to analyze")
      return
    }

    setSastError("")
    setIsSastScanning(true)
    setSastScanResults(null)
    setSastScanStatus("Initializing code analysis...")
    setSastScanProgress(0)

    try {
      const response = await fetch(`${API_BASE_URL}/sast/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code: code.trim(),
          language: selectedLanguage
        })
      })

      const data = await response.json()

      if (response.ok) {
        setCurrentSastScanId(data.scan_id)
        setSastScanStatus("Code analysis started successfully")
      } else {
        setSastError(data.error || "Failed to start code analysis")
        setIsSastScanning(false)
      }
    } catch (err) {
      setSastError("Failed to connect to backend. Make sure the server is running on port 5000.")
      setIsSastScanning(false)
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Critical":
        return "bg-red-600 hover:bg-red-700"
      case "High":
        return "bg-red-500 hover:bg-red-600"
      case "Medium":
        return "bg-yellow-500 hover:bg-yellow-600"
      case "Low":
        return "bg-gray-500 hover:bg-gray-600"
      default:
        return "bg-gray-500 hover:bg-gray-600"
    }
  }

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "Critical":
        return <XCircle className="w-4 h-4" />
      case "High":
        return <XCircle className="w-4 h-4" />
      case "Medium":
        return <AlertTriangle className="w-4 h-4" />
      case "Low":
        return <Info className="w-4 h-4" />
      default:
        return <Info className="w-4 h-4" />
    }
  }

  const filteredResults = scanResults?.vulnerabilities?.filter((result) => {
    const severityMatch = severityFilter === "all" || result.severity === severityFilter
    const categoryMatch = categoryFilter === "all" || 
      result.category === categoryFilter || 
      result.metadata?.category === categoryFilter ||
      result.check_id?.includes(categoryFilter.toLowerCase())
    return severityMatch && categoryMatch
  }) || []

  const downloadResults = (format) => {
    if (!scanResults) return

    const scanType = activeTab === "website" ? "DAST" : "SAST"
    const targetInfo = activeTab === "website" 
      ? `Target: ${scanResults.scan_info.target_url || scanResults.scan_info.target}`
      : `Language: ${scanResults.scan_info.language}\nLines of Code: ${scanResults.scan_info.lines_of_code}`

    const data = format === "json"
      ? JSON.stringify(scanResults, null, 2)
      : `OWASP EYE ${scanType} Scan Results\n
${targetInfo}
Scan Date: ${new Date(scanResults.scan_info.start_time).toLocaleString()}
Duration: ${scanResults.scan_info.duration_seconds}s
Total Vulnerabilities: ${scanResults.summary.total_vulnerabilities}
Risk Score: ${scanResults.summary.risk_score}/100

${filteredResults.map(r => 
  `${activeTab === "code" ? `Check ID: ${r.check_id || 'N/A'}` : `Category: ${r.category || 'N/A'}`}
Title: ${r.description || r.message}
Severity: ${r.severity}
${r.file_path ? `File: ${r.file_path}` : ''}
${r.line_info ? `Line: ${r.line_info.start_line}-${r.line_info.end_line}` : ''}
Details: ${JSON.stringify(r.details || r.metadata, null, 2)}
Discovered: ${new Date(r.discovered_at).toLocaleString()}

`).join('')}`

    const blob = new Blob([data], { type: format === "json" ? "application/json" : "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `owasp-${scanType.toLowerCase()}-scan-results-${Date.now()}.${format === "json" ? "json" : "txt"}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className={`min-h-screen transition-colors duration-300 ${isDarkMode ? "dark bg-gray-900 text-white" : "bg-gray-50 text-gray-900"}`}>
  {/* Header */}
  <header className="border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
    <div className="container mx-auto px-4 py-4 flex items-center justify-between">
      <div className="flex items-center space-x-3">
        <Shield className="w-8 h-8 text-blue-500" />
        <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-500 to-cyan-500 bg-clip-text text-transparent">
          OWASP EYE
        </h1>
      </div>
      <Button variant="ghost" size="icon" onClick={() => setIsDarkMode(!isDarkMode)} className="rounded-full">
        {isDarkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
      </Button>
    </div>
  </header>

  <div className="container mx-auto px-4 py-8">
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
      {/* Main Content */}
      <div className="lg:col-span-3">
        {/* Main Interface Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-2 mb-8">
            <TabsTrigger value="code" className="flex items-center space-x-2">
              <Code className="w-4 h-4" />
              <span>Paste Code</span>
            </TabsTrigger>
            <TabsTrigger value="website" className="flex items-center space-x-2">
              <Globe className="w-4 h-4" />
              <span>Scan Website</span>
            </TabsTrigger>
          </TabsList>

          {/* Tab 1: Code Analysis (SAST) */}
          <TabsContent value="code" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Code className="w-5 h-5" />
                  <span>Static Application Security Testing (SAST)</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {sastError && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
                    <p className="text-sm text-red-800 dark:text-red-200">{sastError}</p>
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Programming Language
                  </label>
                  <Select value={selectedLanguage} onValueChange={setSelectedLanguage} disabled={isSastScanning}>
                    <SelectTrigger className="w-48">
                      <SelectValue placeholder="Select language" />
                    </SelectTrigger>
                    <SelectContent>
                      {supportedLanguages.map((lang) => (
                        <SelectItem key={lang.value} value={lang.value}>
                          {lang.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Paste your source code here for security analysis
                  </label>
                  <Textarea
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder={`// Paste your ${supportedLanguages.find(l => l.value === selectedLanguage)?.label || 'code'} here
// Example:
function login(username, password) {
  var query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
  // This is vulnerable to SQL injection
  return database.query(query);
}`}
                    className="w-full h-64 font-mono text-sm"
                    disabled={isSastScanning}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Lines of code: {code.split('\n').length} | Characters: {code.length}
                  </p>
                </div>

                {isSastScanning && (
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span className="text-sm">{sastScanStatus}</span>
                    </div>
                    <Progress value={sastScanProgress} className="w-full" />
                    <p className="text-xs text-gray-500">{Math.round(sastScanProgress)}% complete</p>
                  </div>
                )}

                <Button
                  onClick={handleScanCode}
                  disabled={!code.trim() || isSastScanning}
                  className="w-full bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600"
                >
                  {isSastScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      Analyzing Code...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Analyze Code Security
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tab 2: Website Scanning (DAST) */}
          <TabsContent value="website" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Globe className="w-5 h-5" />
                  <span>Dynamic Application Security Testing (DAST)</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {dastError && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
                    <p className="text-sm text-red-800 dark:text-red-200">{dastError}</p>
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Enter a website URL to scan for OWASP Top 10 vulnerabilities
                  </label>
                  <Input
                    type="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full"
                    disabled={isDastScanning}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Request Timeout (seconds)
                  </label>
                  <Input
                    type="number"
                    value={timeout}
                    onChange={(e) => setTimeout(parseInt(e.target.value) || 10)}
                    min="5"
                    max="60"
                    className="w-32"
                    disabled={isDastScanning}
                  />
                </div>

                {isDastScanning && (
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span className="text-sm">{dastScanStatus}</span>
                    </div>
                    <Progress value={dastScanProgress} className="w-full" />
                    <p className="text-xs text-gray-500">{Math.round(dastScanProgress)}% complete</p>
                  </div>
                )}

                <Button
                  onClick={handleScanWebsite}
                  disabled={!url.trim() || isDastScanning}
                  className="w-full bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600"
                >
                  {isDastScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      Scanning Website...
                    </>
                  ) : (
                    <>
                      <Rocket className="w-4 h-4 mr-2" />
                      Start Security Scan
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Results Panel */}
        {scanResults && (
          <Card className="mt-8">
            <CardHeader>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-4 sm:space-y-0">
                <div>
                  <CardTitle className="flex items-center space-x-2">
                    <Shield className="w-5 h-5" />
                    <span>{activeTab === "website" ? "DAST" : "SAST"} Security Scan Results</span>
                  </CardTitle>
                  <div className="flex items-center space-x-4 mt-2 text-sm text-gray-600 dark:text-gray-300">
                    {activeTab === "website" ? (
                      <>
                        <span>Target: {scanResults.scan_info.target_url}</span>
                        <span>•</span>
                      </>
                    ) : (
                      <>
                        <span>Language: {scanResults.scan_info.language}</span>
                        <span>•</span>
                        <span>LOC: {scanResults.scan_info.lines_of_code}</span>
                        <span>•</span>
                      </>
                    )}
                    <span>Duration: {scanResults.scan_info.duration_seconds}s</span>
                    <span>•</span>
                    <span>Risk Score: {scanResults.summary.risk_score}/100</span>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="w-full sm:w-32">
                      <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severity</SelectItem>
                      <SelectItem value="Critical">Critical</SelectItem>
                      <SelectItem value="High">High</SelectItem>
                      <SelectItem value="Medium">Medium</SelectItem>
                      <SelectItem value="Low">Low</SelectItem>
                    </SelectContent>
                  </Select>

                  <div className="flex space-x-2">
                    <Button variant="outline" size="sm" onClick={() => downloadResults("json")}>
                      <Download className="w-4 h-4 mr-1" />
                      JSON
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => downloadResults("txt")}>
                      <FileText className="w-4 h-4 mr-1" />
                      Report
                    </Button>
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Summary Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
                <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded">
                  <div className="text-2xl font-bold text-red-600">{scanResults.summary.severity_breakdown?.Critical || 0}</div>
                  <div className="text-sm text-red-600">Critical</div>
                </div>
                <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded">
                  <div className="text-2xl font-bold text-red-500">{scanResults.summary.severity_breakdown?.High || 0}</div>
                  <div className="text-sm text-red-500">High</div>
                </div>
                <div className="text-center p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                  <div className="text-2xl font-bold text-yellow-600">{scanResults.summary.severity_breakdown?.Medium || 0}</div>
                  <div className="text-sm text-yellow-600">Medium</div>
                </div>
                <div className="text-center p-3 bg-gray-50 dark:bg-gray-800 rounded">
                  <div className="text-2xl font-bold text-gray-600">{scanResults.summary.severity_breakdown?.Low || 0}</div>
                  <div className="text-sm text-gray-600">Low</div>
                </div>
              </div>

              {/* Vulnerabilities List */}
              <div className="space-y-4">
                {filteredResults.length === 0 ? (
                  <div className="text-center py-8">
                    <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold mb-2">
                      {scanResults.vulnerabilities.length === 0 ? "No Vulnerabilities Found!" : "No Results Match Current Filters"}
                    </h3>
                    <p className="text-gray-600 dark:text-gray-300">
                      {scanResults.vulnerabilities.length === 0 
                        ? `Great! Your ${activeTab === "website" ? "website" : "code"} appears to be secure against the tested vulnerabilities.`
                        : "Try adjusting your severity filters to see more results."
                      }
                    </p>
                  </div>
                ) : (
                  filteredResults.map((vulnerability) => (
                    <Card key={vulnerability.id} className="border-l-4 border-l-red-500">
                      <CardContent className="pt-4">
                        <div className="flex flex-col space-y-3">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                {activeTab === "website" ? (
                                  <Badge variant="outline" className="text-xs">
                                    {vulnerability.category}
                                  </Badge>
                                ) : (
                                  <Badge variant="outline" className="text-xs">
                                    {vulnerability.check_id}
                                  </Badge>
                                )}
                                <Badge className={`${getSeverityColor(vulnerability.severity)} text-white`}>
                                  {getSeverityIcon(vulnerability.severity)}
                                  <span className="ml-1">{vulnerability.severity}</span>
                                </Badge>
                              </div>
                              <h4 className="font-semibold text-lg mb-2">
                                {vulnerability.description || vulnerability.message}
                              </h4>
                              <div className="flex items-center space-x-4 text-sm text-gray-500 mb-3">
                                <span>Discovered: {new Date(vulnerability.discovered_at).toLocaleString()}</span>
                              </div>

                              {/* Vulnerability Details */}
                              {vulnerability.details && Object.keys(vulnerability.details).length > 0 && (
                                <div className="bg-gray-50 dark:bg-gray-800 rounded p-3">
                                  <p className="text-sm font-medium mb-2">Technical Details:</p>
                                  <div className="space-y-1">
                                    {Object.entries(vulnerability.details).map(([key, value]) => (
                                      <div key={key} className="text-sm">
                                        <span className="font-medium capitalize">{key.replace(/_/g, ' ')}:</span>
                                        <span className="ml-2 font-mono text-xs bg-gray-200 dark:bg-gray-700 px-1 rounded">
                                          {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))
                )}
              </div>

              {/* Recommendations */}
              {scanResults.recommendations && (
                <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded">
                  <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">Security Recommendations:</h4>
                  <ul className="space-y-1">
                    {scanResults.recommendations.map((rec, index) => (
                      <li key={index} className="text-sm text-blue-700 dark:text-blue-300">• {rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Sidebar */}
      <div className="lg:col-span-1">
        <Collapsible open={sidebarOpen} onOpenChange={setSidebarOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="outline" className="w-full mb-4 lg:hidden">
              {sidebarOpen ? <ChevronDown className="w-4 h-4 mr-2" /> : <ChevronRight className="w-4 h-4 mr-2" />}
              Information Panel
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="lg:block">
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">OWASP Top 10 (2021)</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                    This scanner tests for the OWASP Top 10 most critical security risks to web applications.
                  </p>
                  <div className="space-y-2">
                    {owaspCategories.slice(0, 5).map((category, index) => (
                      <div key={category} className="flex items-start space-x-2 text-sm">
                        <span className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs flex-shrink-0 mt-0.5">
                          {index + 1}
                        </span>
                        <span className="leading-tight">{category}</span>
                      </div>
                    ))}
                    <p className="text-xs text-gray-500 mt-2">...and 5 more categories</p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Scanner Features</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>SQL Injection Detection</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>XSS Vulnerability Testing</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>Authentication Analysis</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>Security Headers Check</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>Access Control Testing</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Severity Legend</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2">
                      <XCircle className="w-4 h-4 text-red-600" />
                      <span className="text-sm">Critical - Immediate action required</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <XCircle className="w-4 h-4 text-red-500" />
                      <span className="text-sm">High - Critical security risk</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-yellow-500" />
                      <span className="text-sm">Medium - Moderate risk</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Info className="w-4 h-4 text-gray-500" />
                      <span className="text-sm">Low - Minor security concern</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </CollapsibleContent>
        </Collapsible>
      </div>
    </div>
  </div>

  {/* Footer */}
  <footer className="border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 mt-16">
    <div className="container mx-auto px-4 py-8">
      <div className="text-center space-y-4">
        <p className="text-sm font-medium">© 2025 OWASP EYE – DAST Security Scanner</p>
        <p className="text-xs text-gray-500">This tool is for educational and authorized testing purposes only.</p>
        <div className="flex justify-center space-x-6">
          <Button variant="link" className="p-0 h-auto" asChild>
            <a href="https://github.com" target="_blank" rel="noopener noreferrer">
              <Github className="w-4 h-4 mr-1" />
              GitHub
            </a>
          </Button>
          <Button variant="link" className="p-0 h-auto" asChild>
            <a href="https://owasp.org/Top10" target="_blank" rel="noopener noreferrer">
              <ExternalLink className="w-4 h-4 mr-1" />
              OWASP Top 10
            </a>
          </Button>
        </div>
      </div>
    </div>
  </footer>
</div>
  )
}