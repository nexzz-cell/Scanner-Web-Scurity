const { URL } = require("node:url");
const dns = require("node:dns").promises;
const net = require("node:net");

const MAX_PAGES = 12;
const MAX_BODY = 350_000;
const TIMEOUT_MS = 8000;
const UA = "SecurityFindingLoopholes-Netlify/1.0 (authorized passive audit)";

function isPublicIp(ip) {
  if (net.isIPv4(ip)) {
    const [a,b] = ip.split(".").map(Number);
    if (a===10 || a===127 || a===0 || a===169&&b===254 || a===172&&b>=16&&b<=31 || a===192&&b===168 || a>=224) return false;
    return true;
  }
  if (net.isIPv6(ip)) {
    const x=ip.toLowerCase();
    return !(x==="::1" || x==="::" || x.startsWith("fc") || x.startsWith("fd") || x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb"));
  }
  return false;
}
async function validate(url) {
  let u;
  try { u = new URL(url); } catch { throw new Error("URL tidak valid."); }
  if (!["http:","https:"].includes(u.protocol) || !u.hostname || u.username || u.password) throw new Error("Gunakan URL HTTP/HTTPS yang valid tanpa kredensial.");
  if (u.hostname==="localhost" || u.hostname.endsWith(".local")) throw new Error("Target lokal diblokir.");
  let records;
  try { records=await dns.lookup(u.hostname,{all:true,verbatim:true}); } catch { throw new Error("Domain tidak dapat di-resolve."); }
  if (!records.length || records.some(r=>!isPublicIp(r.address))) throw new Error("Target mengarah ke IP privat/non-publik dan diblokir.");
  return u;
}
function parseHtml(html) {
  const links=[...html.matchAll(/<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)["']/gi)].map(m=>m[1]);
  const forms=[];
  for(const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)){
    const attrs=m[1], action=(attrs.match(/\baction\s*=\s*["']([^"']*)["']/i)||[])[1]||"";
    const method=((attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i)||[])[1]||"get").toUpperCase();
    const fields=[...m[2].matchAll(/<(?:input|select|textarea)\b([^>]*)>/gi)].map(x=>(x[1].match(/\bname\s*=\s*["']([^"']+)["']/i)||[])[1]).filter(Boolean);
    forms.push({action,method,fields:[...new Set(fields)]});
  }
  return {links,forms};
}
async function fetchPage(url, origin) {
  const u=await validate(url);
  if(u.origin!==origin) throw new Error("Cross-origin request blocked.");
  const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),TIMEOUT_MS);
  try {
    const response=await fetch(url,{method:"GET",redirect:"manual",signal:controller.signal,headers:{"user-agent":UA,"accept":"text/html,*/*;q=0.8"}});
    if([301,302,303,307,308].includes(response.status)){
      const loc=response.headers.get("location");
      if(loc){const dest=new URL(loc,url);if(dest.origin!==origin)throw new Error("Cross-origin redirect blocked.");await validate(dest.href);return {response:null,body:"",redirect:dest.href};}
    }
    let body="";
    if((response.headers.get("content-type")||"").toLowerCase().includes("text/html")){
      const reader=response.body?.getReader();
      if(reader){const decoder=new TextDecoder();let total=0;while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>MAX_BODY){reader.cancel();break;}body+=decoder.decode(value,{stream:true});}body+=decoder.decode();}
    }
    return {response,body};
  } finally {clearTimeout(timer);}
}
async function scan(raw, logs) {
  let target=raw.trim();if(!/^https?:\/\//i.test(target))target="https://"+target;
  const start=await validate(target), origin=start.origin;
  const queue=[start.href], seen=[], params=new Set(), forms=[], findings=[], cookies=[];
  let firstHeaders={};
  while(queue.length && seen.length<MAX_PAGES){
    const current=queue.shift();if(seen.includes(current))continue;
    const u=await validate(current);if(u.origin!==origin)continue;
    logs.push("GET "+(u.pathname||"/"));
    try{
      const {response,body,redirect}=await fetchPage(current,origin);
      if(redirect){if(!seen.includes(redirect))queue.push(redirect);continue;}
      seen.push(current);
      if(!Object.keys(firstHeaders).length && response){
        response.headers.forEach((v,k)=>firstHeaders[k.toLowerCase()]=v);
        const setCookie=response.headers.get("set-cookie");
        if(setCookie){
          // Browsers/Node may combine cookie headers; parse conservatively.
          for(const part of setCookie.split(/,(?=\s*[^;,=\s]+=[^;,]*)/)){
            const name=(part.match(/^\s*([^=;\s]+)=/)||[])[1];
            if(name)cookies.push({name,secure:/;\s*secure\b/i.test(part),httponly:/;\s*httponly\b/i.test(part),samesite:(part.match(/;\s*samesite=([^;]+)/i)||[])[1]||null});
          }
        }
      }
      u.searchParams.forEach((_,k)=>params.add(k));
      if(body){
        const parsed=parseHtml(body);
        for(const form of parsed.forms){form.page=current;forms.push(form);form.fields.forEach(x=>params.add(x));}
        for(const href of parsed.links){
          try{const next=new URL(href,current);if(!["http:","https:"].includes(next.protocol)||next.origin!==origin)continue;next.searchParams.forEach((_,k)=>params.add(k));if(!seen.includes(next.href)&&!queue.includes(next.href)&&queue.length<35)queue.push(next.href);}catch{}
        }
      }
    }catch(e){logs.push("SKIP "+u.pathname+" — "+String(e.message||e).slice(0,90));}
  }
  const has=k=>Object.prototype.hasOwnProperty.call(firstHeaders,k);
  const missing=(key,title,detail)=>{if(!has(key))findings.push({title,detail,severity:"REVIEW"});};
  if(start.protocol!=="https:")findings.push({title:"HTTPS tidak digunakan",detail:"Target memakai HTTP. Gunakan HTTPS untuk melindungi data saat transit.",severity:"HIGH"});
  missing("strict-transport-security","HSTS tidak ditemukan","Tinjau Strict-Transport-Security setelah HTTPS aktif.");
  missing("content-security-policy","CSP tidak ditemukan","Content-Security-Policy membantu membatasi sumber konten dan dampak injeksi.");
  missing("x-content-type-options","nosniff tidak ditemukan","Pertimbangkan X-Content-Type-Options: nosniff.");
  missing("referrer-policy","Referrer-Policy tidak ditemukan","Tetapkan kebijakan referrer untuk mengurangi kebocoran URL.");
  missing("permissions-policy","Permissions-Policy tidak ditemukan","Batasi fitur browser yang tidak diperlukan.");
  for(const c of cookies){if(!c.secure&&start.protocol==="https:")findings.push({title:`Cookie ${c.name} tanpa Secure`,detail:"Tinjau atribut Secure untuk cookie sesi pada HTTPS.",severity:"REVIEW"});if(!c.httponly)findings.push({title:`Cookie ${c.name} tanpa HttpOnly`,detail:"Tinjau apakah cookie perlu dilindungi dari akses JavaScript.",severity:"REVIEW"});}
  const idLike=[...params].filter(p=>/^(id|uid|user_id|account_id|order_id|invoice_id|file_id|doc_id)$/i.test(p));
  if(idLike.length)findings.push({title:"Parameter berpotensi terkait object reference",detail:"Nama parameter: "+idLike.join(", ")+". Ini hanya indikator review manual, bukan bukti IDOR. Verifikasi otorisasi dengan akun uji yang sah.",severity:"MANUAL"});
  if(forms.length)findings.push({title:`${forms.length} form ditemukan`,detail:"Form hanya diinventarisasi, tidak dikirim. Tinjau validasi server-side, CSRF, dan otorisasi.",severity:"INFO"});
  if(!findings.length)findings.push({title:"Tidak ada temuan dasar",detail:"Pemeriksaan pasif ini tidak menandai masalah dari daftar pemeriksaan. Ini bukan audit menyeluruh.",severity:"INFO"});
  return {target:origin,pages:seen,parameters:[...params].sort(),forms,cookies,findings,errors:[],checks:{pages_crawled:seen.length,forms_found:forms.length,parameters_found:params.size}};
}

exports.handler = async (event) => {
  const headers={"content-type":"application/json","cache-control":"no-store"};
  if(event.httpMethod!=="POST")return {statusCode:405,headers,body:JSON.stringify({ok:false,error:"Method not allowed."})};
  let input;try{input=JSON.parse(event.body||"{}");}catch{return {statusCode:400,headers,body:JSON.stringify({ok:false,error:"Invalid JSON."})};}
  if(typeof input.url!=="string"||input.url.length>2048)return {statusCode:400,headers,body:JSON.stringify({ok:false,error:"Masukkan URL valid (maksimum 2048 karakter)."})};
  const logs=[];
  try{const result=await scan(input.url,logs);return {statusCode:200,headers,body:JSON.stringify({ok:true,result,logs})};}
  catch(e){return {statusCode:400,headers,body:JSON.stringify({ok:false,error:e.message||"Scan failed.",logs})};}
};
