use std::sync::Arc;

use axum::{response::Html, routing::get, Router};

use crate::AppState;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/ui", get(index))
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

const INDEX: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LazyTeam</title><style>
:root{color-scheme:dark;background:#0b0d10;color:#e7eaf0;font-family:ui-sans-serif,system-ui,sans-serif}body{margin:0}header{padding:24px 28px;border-bottom:1px solid #292e37;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}main{padding:24px;display:grid;gap:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px}.panel{background:#12161c;border:1px solid #292e37;border-radius:12px;padding:16px}h1,h2{margin:0 0 12px}small,.muted{color:#9098a6}.item{padding:10px 0;border-top:1px solid #252a32}.item:first-child{border-top:0}.tag{display:inline-block;padding:2px 7px;margin:2px;border:1px solid #3c4654;border-radius:10px;font-size:12px}.state{font-weight:700}button{background:#2b65d9;color:white;border:0;border-radius:7px;padding:6px 10px;cursor:pointer}button.secondary{background:#414854}input{background:#0b0d10;color:#e7eaf0;border:1px solid #3c4654;border-radius:7px;padding:7px 9px;min-width:260px}.row{display:flex;gap:8px;justify-content:space-between;align-items:center;flex-wrap:wrap}.auth{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.error{color:#ff8c8c}.ok{color:#8fd19e}</style></head>
<body><header><div><h1>LazyTeam</h1><small>Multi-project AI worker control plane</small></div><div class="auth"><input id="admin-token" type="password" autocomplete="off" placeholder="Admin token"><button onclick="saveToken()">Use token</button><button class="secondary" onclick="clearToken()">Clear</button><button onclick="refreshAll()">Refresh</button><small id="auth-status" class="muted">Admin token not set</small></div></header>
<main><section class="grid"><div class="panel"><h2>Projects</h2><div id="projects">Loading…</div></div><div class="panel"><h2>Workers</h2><div id="workers">Loading…</div></div></section><section class="panel"><h2>Tasks</h2><div id="tasks">Loading…</div></section></main>
<script>
const esc=s=>String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));
const TOKEN_KEY='lazyteam.adminToken';
const tokenInput=document.querySelector('#admin-token');
const authStatus=document.querySelector('#auth-status');
function currentToken(){return sessionStorage.getItem(TOKEN_KEY)||''}
function renderAuth(){const token=currentToken();tokenInput.value=token;authStatus.textContent=token?'Admin token stored for this browser session':'Admin token not set';authStatus.className=token?'ok':'muted'}
function saveToken(){const token=tokenInput.value.trim();if(token)sessionStorage.setItem(TOKEN_KEY,token);else sessionStorage.removeItem(TOKEN_KEY);renderAuth();refreshAll()}
function clearToken(){sessionStorage.removeItem(TOKEN_KEY);tokenInput.value='';renderAuth();refreshAll()}
async function json(url,opt={}){const headers=new Headers(opt.headers||{});const token=currentToken();if(token&&url.startsWith('/api/'))headers.set('Authorization','Bearer '+token);const r=await fetch(url,{...opt,headers});if(!r.ok){const body=await r.text();if(r.status===401)throw new Error('Unauthorized: enter the LAZYTEAM_ADMIN_TOKEN above');throw new Error(body||r.statusText)}if(r.status===204)return null;return r.json()}
function tags(t){return Object.entries(t||{}).map(([k,v])=>`<span class="tag">${esc(k)}=${esc(v)}</span>`).join('')}
async function refreshAll(){try{const [p,w,t]=await Promise.all([json('/api/projects'),json('/api/workers'),json('/api/tasks')]);
const pm=Object.fromEntries(p.map(x=>[x.id,x]));
document.querySelector('#projects').innerHTML=p.length?p.map(x=>`<div class="item"><div class="row"><b>${esc(x.name)}</b><span class="state">${x.enabled?'enabled':'disabled'}</span></div><div class="muted">${esc(x.slug)} · ${esc(x.default_branch)}</div><small>${esc(x.repo_url)}</small><div>${tags(x.required_worker_tags)}</div></div>`).join(''):'<span class="muted">No projects</span>';
document.querySelector('#workers').innerHTML=w.length?w.map(x=>`<div class="item"><div class="row"><b>${esc(x.name)}</b><span class="state">${esc(x.state)}</span></div><div class="muted">${esc(x.os)} / ${esc(x.arch)} · slots ${x.running_slots}/${x.slots}</div><div>${tags(x.tags)}</div></div>`).join(''):'<span class="muted">No workers</span>';
document.querySelector('#tasks').innerHTML=t.length?t.map(x=>`<div class="item"><div class="row"><div><b>${esc(x.title)}</b> <span class="tag">${esc(pm[x.project_id]?.slug||x.project_id)}</span></div><span class="state">${esc(x.state)}</span></div><div class="muted">${esc(x.expected_outcome)}</div><div>${tags(x.required_tags)}</div>${x.state==='review'?`<button onclick="transition('${x.id}','approve')">Approve</button> <button class="secondary" onclick="transition('${x.id}','retry')">Retry</button>`:''}${['failed','blocked'].includes(x.state)?`<button class="secondary" onclick="transition('${x.id}','retry')">Retry</button>`:''}</div>`).join(''):'<span class="muted">No tasks</span>';
}catch(e){document.querySelector('#tasks').innerHTML=`<span class="error">${esc(e.message)}</span>`}}
async function transition(id,action){try{await json(`/api/tasks/${id}/${action}`,{method:'POST'});await refreshAll()}catch(e){alert(e.message)}}
renderAuth();refreshAll();setInterval(refreshAll,5000);
</script></body></html>"#;

#[cfg(test)]
mod tests {
    use super::INDEX;

    #[test]
    fn admin_token_is_session_scoped_and_sent_as_bearer() {
        assert!(INDEX.contains("id=\"admin-token\""));
        assert!(INDEX.contains("sessionStorage.setItem(TOKEN_KEY,token)"));
        assert!(INDEX.contains("sessionStorage.removeItem(TOKEN_KEY)"));
        assert!(INDEX.contains("headers.set('Authorization','Bearer '+token)"));
        assert!(INDEX.contains("Unauthorized: enter the LAZYTEAM_ADMIN_TOKEN above"));
    }
}
