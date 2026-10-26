"""Tiny local-only, no-build dashboard for human review (tokens never stored)."""
DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentShield · Human review (local prototype)</title>
<style>
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#0b121b;color:#ebf1f7}
body{max-width:920px;margin:0 auto;padding:2rem 1.25rem}
header{display:flex;align-items:center;gap:1rem;border-bottom:1px solid #283748;padding-bottom:1rem}
h1{margin:0;font-size:1.55rem}p,small{color:#a9bac9}
strong{color:#e8f3ff}label{display:block;margin:1.1rem 0 .4rem}
input{box-sizing:border-box;width:100%;padding:.75rem;border-radius:7px;background:#14202b;color:#fff;border:1px solid #375168}
button{background:#166fb2;color:white;border:0;border-radius:7px;padding:.65rem 1.2rem;margin:.4rem .4rem .2rem 0;cursor:pointer}
button:focus-visible,input:focus-visible{outline:3px solid #83d5ff;outline-offset:2px}
button.secondary{background:#31485d}button.danger{background:#a83838}
article{border:1px solid #32485c;background:#121e2a;border-radius:10px;padding:1rem;margin:1rem 0}
code{overflow-wrap:anywhere;color:#b5d8f4}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#192634;border-radius:8px;padding:1rem}
#status{min-height:1.4rem} .pill{color:#94c3e2}
</style>
</head>
<body>
<header><span aria-hidden="true">🛡️</span><div><h1>AgentShield / Human review</h1>
<small>Offline demonstration only · No real tool execution · Local D1</small></div></header>
<p>This dashboard requires a <strong>separately signed operator JWT</strong> and is
not accessible unless the local smoke flag is enabled. No JWT is stored or logged by this page.</p>
<label for="jwt">Operator Bearer JWT</label>
<input id="jwt" type="password" autocomplete="off" spellcheck="false" placeholder="Paste a temporary operator JWT">
<button id="load">Load approval requests</button><button id="clear" class="secondary">Clear token</button>
<p role="status" aria-live="polite" id="status"></p>
<section id="requests" aria-label="Approval requests"></section>
<pre id="evidence" aria-label="Redacted audit evidence" hidden></pre>
<script>
"use strict";
const token=document.getElementById("jwt");
const status=document.getElementById("status");
const results=document.getElementById("requests");
const evidence=document.getElementById("evidence");
async function api(path,method="GET"){
  const provided=token.value.trim();
  if(!provided)throw new Error("Enter an operator token first");
  const response=await fetch(path,{method,headers:{"Authorization":"Bearer "+provided},
    cache:"no-store",credentials:"omit",redirect:"error"});
  if(!response.ok)throw new Error("Request failed (HTTP "+response.status+")");
  return await response.json();
}
const make=(type,value)=>{const n=document.createElement(type);n.textContent=value;return n};
async function load(){
  results.replaceChildren();evidence.hidden=true;status.textContent="Loading...";
  try{
    const data=await api("/_local/approvals");
    status.textContent=String(data.approvals.length)+" request(s) — local only";
    for(const item of data.approvals){
      const card=document.createElement("article");
      card.appendChild(make("strong",item.action));
      card.appendChild(make("p","Status: "+item.state+" | Expires: "+new Date(item.expires_at_ms).toLocaleString()));
      card.appendChild(make("code","Digest: "+item.action_digest));
      const audit=document.createElement("button");audit.className="secondary";
      audit.textContent="Review audit";
      audit.addEventListener("click",async()=>{try{
        const d=await api("/_local/approvals/"+encodeURIComponent(item.approval_id)+"/audit");
        evidence.textContent=JSON.stringify(d,null,2);evidence.hidden=false;
      }catch(e){status.textContent=e.message}});
      card.appendChild(document.createElement("div")).appendChild(audit);
      if(item.state==="pending"){
        for(const choice of ["approve","reject"]){
          const btn=document.createElement("button");btn.textContent=choice==="approve"?"Approve":"Reject";
          if(choice==="reject")btn.className="danger";
          btn.addEventListener("click",async()=>{
            if(!confirm("Confirm "+choice+" of this exact action digest?"))return;
            try{await api("/_local/approvals/"+encodeURIComponent(item.approval_id)+"/"+choice,"POST");await load()}
            catch(e){status.textContent=e.message}
          });
          card.lastChild.appendChild(btn);
        }
      }
      results.appendChild(card);
    }
  }catch(e){status.textContent=e.message}
}
document.getElementById("load").addEventListener("click",load);
document.getElementById("clear").addEventListener("click",()=>{token.value="";results.replaceChildren();evidence.hidden=true;status.textContent="Token cleared."});
window.addEventListener("pagehide",()=>{token.value=""});
</script>
</body></html>
"""
