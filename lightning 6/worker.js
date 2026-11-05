const SESSION_DAYS = 30;
const MAX_DATA_BYTES = 1800000;
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
}
function randomBytes(n = 32) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(bytes) { let s = ""; for (const x of bytes) s += String.fromCharCode(x); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function unb64(s) { s=s.replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4)s+="="; return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }
async function sha(value) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof value==="string"?encoder.encode(value):value))); }
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt:unb64(salt), iterations:310000, hash:"SHA-256" }, key, 256);
  return b64(new Uint8Array(bits));
}
function cookieValue(request, name) {
  const row=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return row ? decodeURIComponent(row.slice(name.length+1)) : "";
}
function cookie(token, maxAge) {
  return "lightning_session="+encodeURIComponent(token)+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age="+maxAge;
}
async function body(request) {
  const len=Number(request.headers.get("content-length")||0);
  if(len>MAX_DATA_BYTES) throw new Error("Request too large");
  return await request.json();
}
function sameOrigin(request) {
  const origin=request.headers.get("Origin");
  return !origin || origin===new URL(request.url).origin;
}
async function userFor(request, env) {
  const token=cookieValue(request,"lightning_session");
  if(!token) return null;
  const hash=await sha(token), now=Math.floor(Date.now()/1000);
  const row=await env.DB.prepare("SELECT users.id, users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").bind(hash,now).first();
  if(!row) return null;
  return { id:row.id, username:row.username };
}
async function newSession(user, env) {
  const token=b64(randomBytes(32)), now=Math.floor(Date.now()/1000);
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await sha(token),user.id,now+SESSION_DAYS*86400,now).run();
  return token;
}
async function authLimit(request, env) {
  const ip=request.headers.get("CF-Connecting-IP")||"unknown";
  const key=await sha(ip), now=Math.floor(Date.now()/1000);
  await env.DB.prepare("DELETE FROM auth_attempts WHERE attempted_at<?").bind(now-3600).run();
  const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM auth_attempts WHERE ip_hash=? AND attempted_at>?").bind(key,now-900).first();
  return { key, blocked:Number(row?.n||0)>=12, now };
}
async function route(request, env) {
  if(!env.DB) return json({error:"Account database is not configured yet."},503);
  const url=new URL(request.url), path=url.pathname;
  if(path.startsWith("/api/") && !sameOrigin(request)) return json({error:"Origin not allowed."},403);
  if(path==="/api/health" && request.method==="GET") return json({ok:true,service:"Lightning accounts"});
  if(path==="/api/register" && request.method==="POST") {
    let b; try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const username=String(b.username||"").trim(), norm=username.toLowerCase(), password=String(b.password||"");
    if(!/^[A-Za-z0-9_]{3,24}$/.test(username)) return json({error:"Username must be 3–24 characters and use only letters, numbers or underscores."},400);
    if(password.length<10 || password.length>128) return json({error:"Password must be 10–128 characters."},400);
    const exists=await env.DB.prepare("SELECT id FROM users WHERE username_norm=?").bind(norm).first();
    if(exists) return json({error:"That username is already taken."},409);
    const id=b64(randomBytes(18)), salt=b64(randomBytes(16)), hash=await passwordHash(password,salt), now=Math.floor(Date.now()/1000);
    try { await env.DB.prepare("INSERT INTO users(id,username,username_norm,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)").bind(id,username,norm,salt,hash,now).run(); }
    catch { return json({error:"Could not create the account. Try another username."},409); }
    const user={id,username}, token=await newSession(user,env);
    return json({ok:true,user},{status:201,headers:{ "set-cookie":cookie(token,SESSION_DAYS*86400) }});
  }
  if(path==="/api/login" && request.method==="POST") {
    let b; try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const limit=await authLimit(request,env);
    if(limit.blocked) return json({error:"Too many sign-in attempts. Wait 15 minutes and try again."},429);
    const norm=String(b.username||"").trim().toLowerCase(), password=String(b.password||"");
    const row=await env.DB.prepare("SELECT id,username,salt,password_hash FROM users WHERE username_norm=?").bind(norm).first();
    const candidate=row ? await passwordHash(password,row.salt) : await passwordHash(password||"invalid-password",b64(new Uint8Array(16)));
    if(!row || candidate!==row.password_hash) {
      await env.DB.prepare("INSERT INTO auth_attempts(ip_hash,attempted_at) VALUES(?,?)").bind(limit.key,limit.now).run();
      return json({error:"Incorrect username or password."},401);
    }
    await env.DB.prepare("DELETE FROM auth_attempts WHERE ip_hash=?").bind(limit.key).run();
    const token=await newSession(row,env);
    return json({ok:true,user:{id:row.id,username:row.username}},{headers:{"set-cookie":cookie(token,SESSION_DAYS*86400)}});
  }
  if(path==="/api/logout" && request.method==="POST") {
    const token=cookieValue(request,"lightning_session");
    if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha(token)).run();
    return json({ok:true},{headers:{"set-cookie":cookie("",0)}});
  }
  const user=await userFor(request,env);
  if(path==="/api/me" && request.method==="GET") return user?json({user}):json({user:null},401);
  if(path==="/api/data" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    const row=await env.DB.prepare("SELECT data_json,updated_at FROM user_data WHERE user_id=?").bind(user.id).first();
    let data={}; try{data=JSON.parse(row?.data_json||"{}")}catch{}
    return json({data,updatedAt:row?.updated_at||null});
  }
  if(path==="/api/data" && request.method==="PUT") {
    if(!user)return json({error:"Sign in required."},401);
    let b;try{b=await body(request)}catch{return json({error:"Invalid or oversized data."},400)}
    const data=JSON.stringify(b.data??{});
    if(encoder.encode(data).length>MAX_DATA_BYTES)return json({error:"Your saved workspace is too large for this storage limit."},413);
    await env.DB.prepare("INSERT INTO user_data(user_id,data_json,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data_json=excluded.data_json,updated_at=excluded.updated_at").bind(user.id,data,Math.floor(Date.now()/1000)).run();
    return json({ok:true});
  }
  if(path==="/api/share" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const target=String(b.username||"").trim().toLowerCase(), artifact=JSON.stringify(b.artifact??{});
    if(!target)return json({error:"Enter the username to share with."},400);
    if(encoder.encode(artifact).length>500000)return json({error:"That artefact is too large to share."},413);
    const recipient=await env.DB.prepare("SELECT id FROM users WHERE username_norm=?").bind(target).first();
    if(!recipient)return json({error:"No Lightning account found with that username."},404);
    if(recipient.id===user.id)return json({error:"You cannot share an artefact with yourself."},400);
    const id=b64(randomBytes(18));
    await env.DB.prepare("INSERT INTO shares(id,owner_id,recipient_id,artifact_json,created_at) VALUES(?,?,?,?,?)").bind(id,user.id,recipient.id,artifact,Math.floor(Date.now()/1000)).run();
    return json({ok:true,shareId:id});
  }
  if(path.startsWith("/api/share/") && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    const id=decodeURIComponent(path.slice("/api/share/".length));
    const row=await env.DB.prepare("SELECT shares.artifact_json, users.username AS from_username, shares.created_at FROM shares JOIN users ON users.id=shares.owner_id WHERE shares.id=? AND shares.recipient_id=?").bind(id,user.id).first();
    if(!row)return json({error:"Shared artefact not found."},404);
    let artifact={};try{artifact=JSON.parse(row.artifact_json)}catch{}
    return json({artifact,from:row.from_username,createdAt:row.created_at});
  }
  if(path.startsWith("/api/share/") && request.method==="DELETE") {
    if(!user)return json({error:"Sign in required."},401);
    const id=decodeURIComponent(path.slice("/api/share/".length));
    await env.DB.prepare("DELETE FROM shares WHERE id=? AND owner_id=?").bind(id,user.id).run();
    return json({ok:true});
  }
  return env.ASSETS.fetch(request);
}
export default {
  async fetch(request, env, ctx) {
    try { return await route(request,env); }
    catch(e) { return json({error:"Server error. Please try again.",detail:env.ENVIRONMENT==="development"?String(e):undefined},500); }
  }
};
