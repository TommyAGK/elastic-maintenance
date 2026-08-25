"use strict";

const state = {session:null,sources:[],targets:[],jobs:[],sourceToken:"",targetToken:"",jobToken:"",poll:null};
const $ = (selector) => document.querySelector(selector);
const node = (name, options = {}, children = []) => {
  const element = document.createElement(name);
  for (const [key, value] of Object.entries(options)) {
    if (key === "class") element.className = value;
    else if (key === "text") element.textContent = value;
    else if (key.startsWith("data-")) element.setAttribute(key, value);
    else element[key] = value;
  }
  for (const child of children) element.append(child);
  return element;
};
const text = (value, fallback = "—") => value === undefined || value === null || value === "" ? fallback : String(value);
const compactDigest = (digest) => digest && digest.value ? `${digest.version || "v1"}:${digest.value}` : "—";
const timestamp = (value) => value ? new Intl.DateTimeFormat(undefined,{dateStyle:"medium",timeStyle:"short"}).format(new Date(value)) : "—";

async function api(path, options = {}) {
  const response = await fetch(path, {credentials:"same-origin",headers:{Accept:"application/json",...(options.headers || {})},...options});
  let body = null;
  try { body = await response.json(); } catch (_) { /* A safe generic error is shown below. */ }
  if (!response.ok) {
    const error = new Error(body && body.error ? body.error.message : `Request failed (${response.status})`);
    error.status = response.status; error.code = body && body.error ? body.error.code : "request_failed"; throw error;
  }
  return body;
}

function showError(error) {
  const panel = $("#error-state");
  panel.replaceChildren(node("strong",{text:"The requested view could not be loaded."}),node("p",{text:error.message || "Try again."}));
  panel.classList.remove("hidden");
}
function clearError(){ $("#error-state").classList.add("hidden"); }
function toast(message){ const item=$("#toast"); item.textContent=message; item.classList.remove("hidden"); window.setTimeout(()=>item.classList.add("hidden"),3500); }

function activateView(name) {
  const known = ["sources","targets","validations"];
  if (!known.includes(name)) name = "sources";
  document.querySelectorAll("[data-view]").forEach((item)=>item.classList.toggle("hidden",item.dataset.view!==name));
  document.querySelectorAll("[data-view-link]").forEach((item)=>{ const active=item.dataset.viewLink===name; item.classList.toggle("active",active); if(active)item.setAttribute("aria-current","page");else item.removeAttribute("aria-current"); });
  if (location.hash !== `#${name}`) history.replaceState(null,"",`#${name}`);
}

function metric(value,label){ return node("div",{class:"metric"},[node("strong",{text:String(value)}),node("span",{text:label})]); }
function status(value){ return node("span",{class:`status ${value || ""}`,text:text(value)}); }
function digest(value){ const output=node("span",{class:"digest",text:compactDigest(value)}); output.title=compactDigest(value); return output; }
function table(headers, rows) {
  if (!rows.length) return node("p",{class:"empty",text:"No records are available."});
  const head=node("thead",{},[node("tr",{},headers.map((header)=>node("th",{text:header,scope:"col"})))]);
  const body=node("tbody",{},rows.map((cells)=>node("tr",{},cells.map((cell)=>node("td",{},[cell instanceof Node?cell:document.createTextNode(text(cell))])))));
  return node("table",{},[head,body]);
}
function detailHeader(eyebrow,title,onClose){ const close=node("button",{class:"secondary",text:"Close",type:"button"}); close.addEventListener("click",onClose); return node("div",{class:"detail-header"},[node("div",{},[node("p",{class:"eyebrow",text:eyebrow}),node("h2",{text:title})]),close]); }
function definitions(items){ const list=node("dl",{class:"detail-grid"}); for(const [label,value] of items){ list.append(node("div",{class:"definition"},[node("dt",{text:label}),node("dd",{},[value instanceof Node?value:document.createTextNode(text(value))])])); } return list; }
function resourceList(resources) { const list=node("ul",{class:"resource-list"}); for(const entry of resources||[]){ const location=entry.source?`${entry.source.relativePath || "unknown"}:${entry.source.line || 1}`:"—"; list.append(node("li",{class:"resource-item"},[node("code",{text:`${entry.resource.kind}/${entry.resource.id}`}),node("span",{},[node("span",{text:location}),node("span",{class:"location",text:compactDigest(entry.desiredDigest)})]) ])); } if(!list.childElementCount)list.append(node("li",{class:"empty",text:"No resources in this page."})); return list; }

async function loadSources(append=false) {
  clearError(); const path=`/api/v1/sources?pageSize=50${append&&state.sourceToken?`&pageToken=${encodeURIComponent(state.sourceToken)}`:""}`;
  try { const body=await api(path); state.sources=append?state.sources.concat(body.sources):body.sources; state.sourceToken=body.nextPageToken||""; renderSources(); }
  catch(error){ showError(error); }
}
function renderSources(){
  const files=state.sources.reduce((sum,item)=>sum+item.fileCount,0), resources=state.sources.reduce((sum,item)=>sum+item.resourceCount,0);
  $("#source-metrics").replaceChildren(metric(state.sources.length,"Loaded source sets"),metric(files,"Mounted YAML files"),metric(resources,"Typed resources"));
  const rows=state.sources.map((source)=>{ const open=node("button",{class:"row-button",text:source.id,type:"button"}); open.addEventListener("click",()=>openSource(source.id)); return [open,source.revision?source.revision.value:"Not supplied",source.fileCount,source.resourceCount,digest(source.desiredDigest)]; });
  $("#sources-table").replaceChildren(table(["Source set","External revision","Files","Resources","Desired digest"],rows));
  $("#sources-more").classList.toggle("hidden",!state.sourceToken);
}
async function openSource(id){
  try { const body=await api(`/api/v1/sources/${encodeURIComponent(id)}?filePageSize=100&resourcePageSize=100`), item=body.source, panel=$("#source-detail");
    panel.replaceChildren(detailHeader("Source set",item.id,()=>panel.classList.add("hidden")),definitions([["External revision",item.revision?item.revision.value:"Not supplied"],["Revision metadata file",item.revision?item.revision.relativePath:"—"],["Desired digest",digest(item.desiredDigest)],["Files in page",item.files.length],["Resources in page",item.resources.length]]),node("p",{class:"readonly",text:"Read-only view. Update this source through its external GitOps workflow; Elastic Maintainer never writes mounted content."}),node("h3",{text:"Resources"}),resourceList(item.resources));
    if(body.nextFilePageToken||body.nextResourcePageToken)panel.append(node("p",{class:"location",text:"This large source set has additional paginated file or resource metadata available through /api/v1."})); panel.classList.remove("hidden"); panel.scrollIntoView({behavior:"smooth",block:"start"});
  }catch(error){showError(error);}
}

async function loadTargets(append=false){
  clearError(); const path=`/api/v1/targets?pageSize=50${append&&state.targetToken?`&pageToken=${encodeURIComponent(state.targetToken)}`:""}`;
  try{const body=await api(path);state.targets=append?state.targets.concat(body.targets):body.targets;state.targetToken=body.nextPageToken||"";renderTargets();}catch(error){showError(error);}
}
function renderTargets(){
  const sources=new Set(state.targets.map((item)=>item.resourceSetID)); const resources=state.targets.reduce((sum,item)=>sum+item.resourceCount,0);
  $("#target-metrics").replaceChildren(metric(state.targets.length,"Loaded targets"),metric(sources.size,"Assigned source sets"),metric(resources,"Applicable resources"));
  const rows=state.targets.map((target)=>{const open=node("button",{class:"row-button",text:target.identity.name,type:"button"});open.addEventListener("click",()=>openTarget(target.identity.name));return[open,target.resourceSetID,target.revision||"Not supplied",target.identity.space,target.resourceCount,digest(target.desiredDigest)];});
  $("#targets-table").replaceChildren(table(["Target","Source set","Revision","Space","Resources","Desired digest"],rows)); $("#targets-more").classList.toggle("hidden",!state.targetToken);
}
async function openTarget(id){
  try{const encoded=encodeURIComponent(id),[body,credential,readiness]=await Promise.all([api(`/api/v1/targets/${encoded}?pageSize=100`),api(`/api/v1/targets/${encoded}/credential-status`),api(`/api/v1/targets/${encoded}/readiness`)]),item=body.target,panel=$("#target-detail");const labels=(item.labels||[]).map((label)=>`${label.key}=${label.value}`).join(", ")||"None";
    panel.replaceChildren(detailHeader("Kibana target",item.identity.name,()=>panel.classList.add("hidden")),definitions([["Source set",item.resourceSetID],["External revision",item.revision||"Not supplied"],["Kibana URL",item.identity.url],["Space",item.identity.space],["Labels",labels],["Desired digest",digest(item.desiredDigest)],["Credential",credential.credentialStatus.configured?"Configured":"Not configured"],["Readiness",readiness.ready?`Ready · ${readiness.kibanaVersion}`:`Not ready · ${readiness.failureCode||"unavailable"}`]]),node("p",{class:"readonly",text:"Target assignment and desired resources are read-only. Update mounted server configuration through the external deployment workflow."}),node("h3",{text:"Applicable resources"}),resourceList(item.resources));
    if(body.nextResourcePageToken)panel.append(node("p",{class:"location",text:"Additional resource metadata is available through the paginated /api/v1 endpoint."}));panel.append(targetOperations(id,credential.credentialStatus));panel.classList.remove("hidden");panel.scrollIntoView({behavior:"smooth",block:"start"});
  }catch(error){showError(error);}
}
function targetOperations(id,credential){const section=node("section",{class:"target-operations"},[node("h3",{text:"Live inventory"})]),refresh=node("button",{class:"secondary",type:"button",text:"Refresh live inventory"}),output=node("div",{class:"live-output"});refresh.addEventListener("click",()=>startTargetInventory(id,refresh,output));section.append(refresh,output);const roles=state.session&&state.session.actor?state.session.actor.roles||[]:[];if(!roles.includes("administrator"))return section;const form=node("form",{class:"credential-form",autocomplete:"off"}),apiKey=node("input",{type:"password",required:true,maxLength:16384,autocomplete:"off"}),ca=node("textarea",{maxLength:262144,rows:5}),submit=node("button",{class:"button",type:"submit",text:credential.configured?"Rotate credential":"Upload credential"}),remove=node("button",{class:"secondary",type:"button",text:"Delete credential"});form.append(node("h3",{text:"Administrator credential controls"}),node("label",{text:"Kibana API key"}),apiKey,node("label",{text:"Optional CA certificate bundle"}),ca,submit,remove);form.addEventListener("submit",async(event)=>{event.preventDefault();submit.disabled=true;try{const key=`web-${Date.now()}-${crypto.randomUUID()}`,payload=JSON.stringify({apiKey:apiKey.value,caCertificatePem:ca.value});apiKey.value="";ca.value="";await api(`/api/v1/targets/${encodeURIComponent(id)}/credentials`,{method:"PUT",headers:{"Content-Type":"application/json","Idempotency-Key":key,"X-CSRF-Token":state.session.csrfToken},body:payload});toast("Credential stored. Values cannot be retrieved.");await openTarget(id);}catch(error){showError(error);}finally{apiKey.value="";ca.value="";submit.disabled=false;}});remove.addEventListener("click",async()=>{if(!window.confirm("Delete this target credential? Active jobs prevent deletion."))return;remove.disabled=true;try{await api(`/api/v1/targets/${encodeURIComponent(id)}/credentials`,{method:"DELETE",headers:{"Content-Type":"application/json","Idempotency-Key":`web-${Date.now()}-${crypto.randomUUID()}`,"X-CSRF-Token":state.session.csrfToken},body:JSON.stringify({confirm:true})});toast("Credential deleted.");await openTarget(id);}catch(error){showError(error);}finally{remove.disabled=false;}});section.append(form);return section;}
async function startTargetInventory(id,button,output){button.disabled=true;try{const body=await api(`/api/v1/targets/${encodeURIComponent(id)}/inventory`,{method:"POST",headers:{"Content-Type":"application/json","Idempotency-Key":`web-${Date.now()}-${crypto.randomUUID()}`,"X-CSRF-Token":state.session.csrfToken},body:"{}"});await pollTargetInventory(id,body.job.id,output);}catch(error){showError(error);}finally{button.disabled=false;}}
async function pollTargetInventory(targetID,jobID,output){const base=`/api/v1/targets/${encodeURIComponent(targetID)}/inventory/${encodeURIComponent(jobID)}`;let body;do{body=await api(`${base}?pageSize=100`);output.replaceChildren(definitions([["Status",status(body.job.status)],["Kibana version",body.kibanaVersion||"—"],["Checked",timestamp(body.checkedAt)]]));if(body.job.status==="queued"||body.job.status==="running")await new Promise((resolve)=>window.setTimeout(resolve,1500));}while(body.job.status==="queued"||body.job.status==="running");const resources=[...(body.resources||[])];let token=body.nextPageToken||"";while(token){const page=await api(`${base}?pageSize=100&pageToken=${encodeURIComponent(token)}`);resources.push(...(page.resources||[]));token=page.nextPageToken||"";}if(resources.length)output.append(table(["Kind","ID","Name","Manageable","Fingerprint"],resources.map((item)=>[item.kind,item.id,item.name,item.manageable?"Yes":"No",item.fingerprint?item.fingerprint.value:"—"])));}

async function loadValidations(append=false){
  clearError();const path=`/api/v1/validations?pageSize=50${append&&state.jobToken?`&pageToken=${encodeURIComponent(state.jobToken)}`:""}`;
  try{const body=await api(path);state.jobs=append?state.jobs.concat(body.jobs):body.jobs;state.jobToken=body.nextPageToken||"";renderValidations();}catch(error){showError(error);}
}
function renderValidations(){
  const rows=state.jobs.map((job)=>{const open=node("button",{class:"row-button",text:job.id,type:"button"});open.addEventListener("click",()=>openValidation(job.id));return[open,status(job.status),timestamp(job.createdAt),job.actorSubject,job.failureCode||"—"];});
  $("#validations-table").replaceChildren(table(["Validation","Status","Created","Requested by","Outcome"],rows)); $("#validations-more").classList.toggle("hidden",!state.jobToken);
}
async function startValidation(){
  const button=$("#start-validation");button.disabled=true;button.textContent="Starting…";
  try{const key=`web-${Date.now()}-${crypto.randomUUID()}`;const body=await api("/api/v1/validations",{method:"POST",headers:{"Content-Type":"application/json","Idempotency-Key":key,"X-CSRF-Token":state.session.csrfToken},body:"{}"});toast("Validation queued.");await loadValidations();activateView("validations");await openValidation(body.job.id);}
  catch(error){showError(error);}finally{button.disabled=false;button.textContent="Validate all mounts";}
}
async function openValidation(id){
  if(state.poll){clearTimeout(state.poll);state.poll=null;}
  try{const body=await api(`/api/v1/validations/${encodeURIComponent(id)}?diagnosticPageSize=100&sourcePageSize=100&targetPageSize=100`),job=body.job,panel=$("#validation-detail");
    const content=[detailHeader("Validation job",job.id,()=>{panel.classList.add("hidden");if(state.poll)clearTimeout(state.poll);}),definitions([["Status",status(job.status)],["Created",timestamp(job.createdAt)],["Started",timestamp(job.startedAt)],["Finished",timestamp(job.finishedAt)],["Requested by",job.actorSubject],["Failure code",job.failureCode||"—"]])];
    if(body.result){content.push(node("h3",{text:body.result.valid?"Validated inventory":"Diagnostics"}));content.push(definitions([["Result",body.result.valid?"Valid":"Invalid"],["Source sets",body.result.counts.resourceSets],["Targets",body.result.counts.targets],["Resources",body.result.counts.resources],["Files",body.result.counts.files]]));
      const diagnostics=node("ul",{class:"diagnostics"});for(const item of body.result.diagnostics||[]){const location=item.location?`${item.location.resourceSetID || ""}/${item.location.relativePath || ""}:${item.location.line || 1}`:(item.target||item.resourceSetID||"No source location");diagnostics.append(node("li",{class:"diagnostic"},[node("code",{text:item.code}),node("p",{},[document.createTextNode(item.message),node("span",{class:"location",text:location})])]));}if(diagnostics.childElementCount)content.push(diagnostics);
      if(body.result.sources.length||body.result.targets.length){content.push(node("p",{class:"location",text:`Historical result: ${body.result.sources.length} source summaries and ${body.result.targets.length} target summaries in this page.`}));}
      if(body.result.nextDiagnosticPageToken||body.result.nextSourcePageToken||body.result.nextTargetPageToken)content.push(node("p",{class:"location",text:"Additional historical result metadata is available through paginated /api/v1 responses."}));
    }else content.push(node("p",{class:"readonly",text:"This job has not produced a result yet. The view refreshes while it is queued or running."}));
    panel.replaceChildren(...content);panel.classList.remove("hidden");panel.scrollIntoView({behavior:"smooth",block:"start"});
    if(job.status==="queued"||job.status==="running")state.poll=window.setTimeout(async()=>{await loadValidations();await openValidation(id);},1500);
  }catch(error){showError(error);}
}

async function breakGlassLogin(event){
  event.preventDefault();const form=event.currentTarget,username=$("#break-glass-username"),password=$("#break-glass-password"),error=$("#break-glass-error"),button=form.querySelector("button");button.disabled=true;error.classList.add("hidden");
  try{await api("/auth/break-glass/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:username.value,password:password.value})});location.assign("/");}catch(failure){error.textContent=failure.message||"Authentication failed.";error.classList.remove("hidden");}finally{password.value="";button.disabled=false;}
}

async function logout(){
  const button=$("#logout");button.disabled=true;
  try{await api("/auth/logout",{method:"POST",headers:{"X-CSRF-Token":state.session.csrfToken}});location.assign("/");}catch(error){button.disabled=false;showError(error);}
}

async function boot(){
  window.addEventListener("hashchange",()=>activateView(location.hash.slice(1)));
  document.querySelectorAll("[data-refresh]").forEach((button)=>button.addEventListener("click",()=>button.dataset.refresh==="sources"?loadSources():loadTargets()));
  $("#sources-more").addEventListener("click",()=>loadSources(true));$("#targets-more").addEventListener("click",()=>loadTargets(true));$("#validations-more").addEventListener("click",()=>loadValidations(true));$("#start-validation").addEventListener("click",startValidation);$("#logout").addEventListener("click",logout);$("#break-glass-login").addEventListener("submit",breakGlassLogin);
  try{state.session=await api("/api/v1/session");}catch(error){if(error.status===401){$("#auth-state").classList.remove("hidden");$("#identity").textContent="Not signed in";return;}showError(error);return;}
  const actor=state.session.actor,roles=actor.roles||[],method=state.session.authenticationMethod||"session";$("#identity").replaceChildren(node("span",{class:"status-dot"}),document.createTextNode(`${actor.displayName||actor.subject} · ${roles.join(", ")||"no role"} · ${method}`));$("#logout").classList.remove("hidden");if(method==="break-glass"){$("#break-glass-expiry").textContent=`Absolute expiry: ${timestamp(state.session.expiresAt)}`;$("#break-glass-banner").classList.remove("hidden");}
  const canValidate=roles.includes("planner")||roles.includes("administrator");$("#start-validation").classList.toggle("hidden",!canValidate);$("#validation-permission").classList.toggle("hidden",canValidate);$("#workspace").classList.remove("hidden");activateView(location.hash.slice(1)||location.pathname.slice(1));await Promise.all([loadSources(),loadTargets(),loadValidations()]);
}

boot();
