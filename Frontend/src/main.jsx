import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Link, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import axios from 'axios'
import { Activity, ArrowRight, CheckCircle2, LockKeyhole, ShieldCheck, XCircle } from 'lucide-react'
import './styles.css'
import jsPDF from "jspdf"

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || '/api', timeout: 15000 })
const Disclaimer = () => <p className="disclaimer">Only scan websites you own or are authorized to assess. VulnScan Lite performs passive analysis only.</p>

const Layout = ({ children }) => <>
  <header>
    <Link to="/" className="brand"><ShieldCheck /> VulnScan <span>Lite</span></Link>
    <div className="status-chip"><span className="status-dot" aria-hidden="true"></span>Systems nominal</div>
    <nav><Link to="/scan">Scan</Link><Link to="/history">History</Link></nav>
  </header>
  <main>{children}</main>
  <footer><Disclaimer /></footer>
</>

function Home() {
  return <Layout>
    <section className="hero specimen">
      <div className="eyebrow"><LockKeyhole size={15}/> Passive security assessment</div>
      <h1>Know Your Website<br/>Security in Seconds</h1>
      <p>Passive website security assessment for developers, startups, and business owners.</p>
      <Link className="button" to="/scan">Start Scan <ArrowRight size={18}/></Link>
    </section>
    <section className="features">
      {[[ShieldCheck,'Security headers'],[LockKeyhole,'TLS inspection'],[Activity,'Technology analysis']].map(([Icon,text])=>
        <article key={text}><div className="feature-mark"><Icon/></div><h3>{text}</h3><p>Clear, actionable signals from a safe, non-intrusive assessment.</p></article>
      )}
    </section>
  </Layout>
}

function Scan() {
  const [url,setUrl]=useState('')
  const [error,setError]=useState('')
  const [loading,setLoading]=useState(false)
  const nav=useNavigate()
  const submit=async e=>{
    e.preventDefault();setError('');setLoading(true)
    try { const {data}=await api.post('/api/scan',{url}); nav(`/scan/${data.id}`) }
    catch(e) { setError(e.response?.data?.detail || 'Unable to start scan. Please check the URL and try again.') }
    finally {setLoading(false)}
  }
  return <Layout>
    <section className="panel narrow">
      <div className="eyebrow">New assessment</div>
      <h2>Scan a website you manage</h2>
      <p>We inspect public response metadata only. No exploitation, probing, or intrusive requests.</p>
      <form onSubmit={submit}>
        <label htmlFor="url">Website URL</label>
        <div className="input-row">
          <input id="url" type="url" required placeholder="https://example.com" value={url} onChange={e=>setUrl(e.target.value)}/>
          <button disabled={loading}>{loading?'Queueing…':'Start scan'}</button>
        </div>
      </form>
      {error&&<p className="error">{error}</p>}
      <Disclaimer />
    </section>
  </Layout>
}

function Status() {
  const {id}=useParams()
  const [scan,setScan]=useState()
  const [error,setError]=useState('')
  const nav=useNavigate()
  useEffect(()=>{
    let timer
    const poll=async()=>{
      try {const {data}=await api.get(`/api/scan/${id}/status`);setScan(data);if(data.status==='completed') nav(`/report/${id}`); else if(data.status!=='failed') timer=setTimeout(poll,2000)}
      catch(e){setError('Could not retrieve this scan.')}
    }
    poll()
    return()=>clearTimeout(timer)
  },[id,nav])
  return <Layout>
    <section className="panel narrow center">
      <div className="radar" aria-hidden="true"><span></span><span></span><span></span></div>
      <h2>{scan?.status==='running'?'Analyzing security signals':'Scan queued'}</h2>
      <p>{scan?.status==='failed' ? scan.error || 'The scan could not be completed.' : 'This page updates automatically.'}</p>
      {error&&<p className="error">{error}</p>}
      <code className="ref">REF {id}</code>
    </section>
  </Layout>
}

const Seal = ({ grade }) => (
  <div className="seal" aria-hidden="true">
    <span className="seal-top">VulnScan</span>
    <span className="seal-grade">{grade}</span>
    <span className="seal-bottom">Assessed</span>
  </div>
)

function Report() {
  const { id } = useParams()
  const [report, setReport] = useState()
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .get(`/api/scan/${id}/result`)
      .then((r) => {
        setReport(r.data)

        const history = JSON.parse(
          localStorage.getItem("history") || "[]"
        )

        history.unshift({
          id,
          date: new Date().toLocaleString(),
          url: r.data.url,
          score: r.data.score,
          risk: r.data.risk_level
        })

        localStorage.setItem(
          "history",
          JSON.stringify(history)
        )
      })
      .catch((e) =>
        setError(
          e.response?.data?.detail ||
            "Report not available."
        )
      )
  }, [id])

  if (error)
    return (
      <Layout>
        <section className="panel">
          <p className="error">{error}</p>
        </section>
      </Layout>
    )

  if (!report)
    return (
      <Layout>
        <section className="panel center">
          <div className="radar" aria-hidden="true"><span></span><span></span><span></span></div>
          Loading report...
        </section>
      </Layout>
    )

  const checks = Object.entries(report.headers || {})
  const downloadPDF = () => {
    const doc = new jsPDF()

    doc.setFontSize(20)
    doc.text("VulnScan Lite Security Report", 20, 20)

    doc.setFontSize(12)
    doc.text(`URL: ${report.url}`, 20, 40)
    doc.text(`Score: ${report.score}/100`, 20, 50)
    doc.text(`Grade: ${report.grade}`, 20, 60)
    doc.text(`Risk Level: ${report.risk_level}`, 20, 70)

    doc.text(`Passed Checks: ${report.summary.passed}`, 20, 90)
    doc.text(`Failed Checks: ${report.summary.failed}`, 20, 100)

    doc.save("VulnScan-Report.pdf")
  }

  return (
    <Layout>
      <section className="report-head">
        <div>
          <div className="eyebrow">Security Report</div>
          <h2>{report.url}</h2>
          <p>
            Completed{" "}
            {new Date(report.completed_at).toLocaleString()}
          </p>
          <button className="ghost" onClick={downloadPDF}>Download PDF</button>
        </div>

        <div className="score-block">
          <div className="score">
            <strong>{report.score}</strong>
            <span>/ 100</span>
          </div>
          <Seal grade={report.grade} />
        </div>
      </section>

      <section className="metrics">
        <article>
          <span>Total checks</span>
          <strong>{report.summary.total}</strong>
        </article>

        <article>
          <span>Passed</span>
          <strong className="good">
            {report.summary.passed}
          </strong>
        </article>

        <article>
          <span>Failed</span>
          <strong className="bad">
            {report.summary.failed}
          </strong>
        </article>

        <article>
          <span>Risk level</span>
          <strong>{report.risk_level}</strong>
        </article>
      </section>

      <section className="panel">
        <h2>Security Headers</h2>

        <div className="table">
          <div className="table-row table-row-head">
            <span>Header</span><span>Status</span><span>Impact</span>
          </div>
          {checks.map(([header, result]) => (
            <div className="table-row" key={header}>
              <span className="mono">{header}</span>

              <span
                className={result.present ? "good" : "bad"}
              >
                {result.present ? (
                  <CheckCircle2 />
                ) : (
                  <XCircle />
                )}
                {result.present ? " Present" : " Missing"}
              </span>

              <span>{result.impact}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="split">
        <section className="panel">
          <h2>SSL / TLS</h2>

          <p>
            <b>Status:</b>{" "}
            {report.ssl.valid ? "Valid" : "Needs attention"}
          </p>

          <p>
            <b>Issuer:</b>{" "}
            {report.ssl.issuer || "Unavailable"}
          </p>

          <p>
            <b>Expires:</b>{" "}
            {report.ssl.expires || "Unavailable"}
          </p>

          <p>
            <b>TLS:</b>{" "}
            {report.ssl.tls_version || "Unavailable"}
          </p>
        </section>

        <section className="panel">
          <h2>Server Analysis</h2>

          <p>
            <b>Server:</b>{" "}
            {report.server.server || "Not disclosed"}
          </p>

          <p>
            <b>Powered by:</b>{" "}
            {report.server.powered_by || "Not disclosed"}
          </p>

          <p>
            <b>CMS:</b>{" "}
            {report.cms.name || "Not detected"}
          </p>
        </section>
      </section>
    </Layout>
  )
}

function History() {
  const scans = JSON.parse(localStorage.getItem("history") || "[]")

  return (
    <Layout>
      <section className="panel">
        <h2>Recent Scans</h2>

        {scans.length === 0 ? (
          <p>No scan history available.</p>
        ) : (
          <div className="stub-list">
            {scans.map((scan, index) => (
              <div className="stub" key={index}>
                <div className="stub-id mono">#{String(scan.id).slice(0,8)}</div>
                <div className="stub-body">
                  <p className="stub-url">{scan.url}</p>
                  <p className="stub-meta">{scan.date}</p>
                </div>
                <div className="stub-score">
                  <strong>{scan.score}</strong>
                  <span className={/low/i.test(scan.risk) ? "good" : /high|critical/i.test(scan.risk) ? "bad" : "warn"}>{scan.risk}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </Layout>
  )
}

function App(){return <Routes><Route path="/" element={<Home/>}/><Route path="/scan" element={<Scan/>}/><Route path="/scan/:id" element={<Status/>}/><Route path="/report/:id" element={<Report/>}/><Route path="/history" element={<History/>}/></Routes>}
createRoot(document.getElementById('root')).render(<React.StrictMode><BrowserRouter><App/></BrowserRouter></React.StrictMode>)