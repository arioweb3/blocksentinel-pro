const $ = (id) => document.getElementById(id);
const sourceEl = $("source"), filenameEl = $("filename");
let latestReport = null;
const sample = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RiskyVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
    function ownerCheck() external view returns (address) { return tx.origin; }
}`;
function esc(v){return String(v ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));}
$("load-example").addEventListener("click",()=>{sourceEl.value=sample;filenameEl.value="RiskyVault.sol";});
function renderFinding(f){return `<article class="finding"><div class="finding-head"><span class="badge ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span><div><h4>${esc(f.title)}</h4><div class="meta">${esc(f.id)} · line ${f.line} · ${esc(f.confidence)} · ${esc(f.detector)}</div></div></div><p>${esc(f.description)}</p><div class="code-snippet">L${f.line} &nbsp; ${esc(f.snippet || "(source context unavailable)")}</div><div class="recommendation"><b>RECOMMENDATION</b><br>${esc(f.recommendation)}</div></article>`;}
async function getReport(path){const res=await fetch("https://ghastly-owl-4q65wpg7j4jv27vw6-8000.app.github.dev" + path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source:sourceEl.value,filename:filenameEl.value||"Contract.sol",use_slither:$("use-slither").checked,use_ast:$("use-ast").checked})});if(!res.ok){let data={};try{data=await res.json()}catch{}throw new Error(data.detail||`Request failed (${res.status})`)}return res;}
$("analyze").addEventListener("click",async()=>{
  $("error").hidden=true;
  if(!sourceEl.value.trim()){$("error").textContent="Paste Solidity source before running analysis.";$("error").hidden=false;return;}
  $("analyze").disabled=true;$("run-status").innerHTML="<i></i> ANALYZING";
  try{
    const res=await getReport("/api/analyze");latestReport=await res.json();
    $("empty-state").hidden=true;$("report").hidden=false;
    for(const s of ["high","medium","low","info"])$(s+"-count").textContent=latestReport.summary[s]??0;
    $("finding-count").textContent=latestReport.findings.length;
    $("findings").innerHTML=latestReport.findings.length?latestReport.findings.map(renderFinding).join(""):'<div class="output-empty"><h3>No heuristic findings</h3><p>This does not prove the contract is secure. Use compiler-aware analysis and manual review.</p></div>';
    $("tools-status").innerHTML=Object.entries(latestReport.tools).map(([k,v])=>`<div><b>${esc(k.toUpperCase())}</b> — ${esc(v)}</div>`).join("");
    $("disclaimer").textContent=latestReport.disclaimer;$("run-status").innerHTML="<i></i> COMPLETE";
    const previous=localStorage.getItem("bs-current");
    if(previous)localStorage.setItem("bs-previous",previous);
    localStorage.setItem("bs-current",JSON.stringify(latestReport));
  }catch(e){$("error").textContent=e.message||"Unexpected error";$("error").hidden=false;$("run-status").textContent="ERROR";}
  finally{$("analyze").disabled=false;}
});
async function downloadReport(path,filename,type){try{const r=await getReport(path);const data=type==="json"?JSON.stringify(await r.json(),null,2):await r.text();const blob=new Blob([data],{type});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=filename;a.click();URL.revokeObjectURL(url);}catch(e){$("error").textContent=e.message;$("error").hidden=false;}}
$("download-md").addEventListener("click",()=>downloadReport("/api/report/markdown","blocksentinel-report.md","text/markdown;charset=utf-8"));
$("download-sarif").addEventListener("click",()=>downloadReport("/api/report/sarif","blocksentinel.sarif","application/sarif+json"));
$("save-baseline").addEventListener("click",()=>{if(!latestReport){$("compare-result").textContent="Run a scan first.";return;}localStorage.setItem("bs-baseline",JSON.stringify(latestReport));$("compare-result").textContent="Baseline saved in this browser's local storage.";});
$("compare-baseline").addEventListener("click",async()=>{
  const raw=localStorage.getItem("bs-baseline");
  if(!raw||!latestReport){$("compare-result").textContent="Save a baseline and run a current scan first.";return;}
  try{
    const baseline=JSON.parse(raw);
    const r=await fetch("/api/compare",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({baseline:baseline.findings,current:latestReport.findings})});
    const data=await r.json();$("compare-result").textContent=`Introduced: ${data.summary.introduced} · Resolved: ${data.summary.resolved} · Unchanged: ${data.summary.unchanged}`;
  }catch(e){$("compare-result").textContent="Comparison failed. Please rerun analysis.";}
});
// Ambient cinematic particle field. Visual only; does not claim to connect to a live chain.
(() => {
  const canvas=$("cosmos"),ctx=canvas.getContext("2d");let w=0,h=0,dpr=1,particles=[],t=0;
  function resize(){dpr=Math.min(window.devicePixelRatio||1,2);w=innerWidth;h=innerHeight;canvas.width=w*dpr;canvas.height=h*dpr;canvas.style.width=w+"px";canvas.style.height=h+"px";ctx.setTransform(dpr,0,0,dpr,0,0);particles=Array.from({length:Math.min(100,Math.floor(w*h/13000))},()=>({x:Math.random()*w,y:Math.random()*h,z:Math.random(),r:.5+Math.random()*1.4,v:.12+Math.random()*.38,phase:Math.random()*Math.PI*2}));}
  function draw(){ctx.clearRect(0,0,w,h);t+=.003;const pts=particles.map(p=>{p.y-=p.v*.25;if(p.y<0)p.y=h;return {...p,px:p.x+Math.sin(t+p.phase)*10,py:p.y};});
    for(let i=0;i<pts.length;i++){const a=pts[i];for(let j=i+1;j<pts.length;j++){const b=pts[j],dx=a.px-b.px,dy=a.py-b.py,d=Math.hypot(dx,dy);if(d<115){ctx.strokeStyle=`rgba(91,224,200,${(1-d/115)*.12})`;ctx.lineWidth=.6;ctx.beginPath();ctx.moveTo(a.px,a.py);ctx.lineTo(b.px,b.py);ctx.stroke();}}}
    for(const p of pts){ctx.fillStyle=`rgba(144,255,231,${.18+p.z*.45})`;ctx.beginPath();ctx.arc(p.px,p.py,p.r,0,Math.PI*2);ctx.fill();}
    requestAnimationFrame(draw);
  }
  resize();addEventListener("resize",resize);draw();
})();
