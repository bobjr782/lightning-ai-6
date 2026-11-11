const SESSION_DAYS = 30;
const MAX_DATA_BYTES = 20000000;
let accountTablesReady = false;
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
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt:unb64(salt), iterations:100000, hash:"SHA-256" }, key, 256);
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
  const raw=await request.text();
  if(encoder.encode(raw).length>MAX_DATA_BYTES) throw new Error("Request too large");
  return JSON.parse(raw);
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

async function ensureSocialTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS friendships (
    user_low TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_high TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(user_low,user_high)
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS friend_requests (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    UNIQUE(sender_id,recipient_id)
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS friend_requests_recipient_idx ON friend_requests(recipient_id,status,created_at)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS direct_messages (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, message TEXT NOT NULL, created_at INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS direct_messages_pair_idx ON direct_messages(sender_id,recipient_id,created_at)").run();
}
function friendPair(a,b){return a<b?[a,b]:[b,a];}

const FRIEND_CODE_CHARS="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
async function ensureProfile(user,env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS user_profiles (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    friend_code TEXT NOT NULL UNIQUE,
    avatar_data TEXT,
    updated_at INTEGER NOT NULL
  )`).run();
  let profile=await env.DB.prepare("SELECT friend_code,avatar_data FROM user_profiles WHERE user_id=?").bind(user.id).first();
  if(!profile){
    for(let attempt=0;attempt<12&&!profile;attempt++){
      const bytes=randomBytes(5);let code="";
      for(const byte of bytes)code+=FRIEND_CODE_CHARS[byte%FRIEND_CODE_CHARS.length];
      await env.DB.prepare("INSERT OR IGNORE INTO user_profiles(user_id,friend_code,avatar_data,updated_at) VALUES(?,?,NULL,?)").bind(user.id,code,Math.floor(Date.now()/1000)).run();
      profile=await env.DB.prepare("SELECT friend_code,avatar_data FROM user_profiles WHERE user_id=?").bind(user.id).first();
    }
  }
  if(!profile)throw new Error("Could not allocate a Lightning friend key. Please try again.");
  return profile;
}

async function ensureAccountTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL, username_norm TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at)").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS auth_attempts (
    ip_hash TEXT NOT NULL, attempted_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS auth_attempts_ip_time_idx ON auth_attempts(ip_hash,attempted_at)").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS user_data (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL DEFAULT '{}', object_key TEXT, updated_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    artifact_json TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(owner_id,recipient_id,id)
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS shares_recipient_idx ON shares(recipient_id,created_at)").run();
}

async function ensurePublishedTable(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS published_artifacts (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    code TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS published_artifacts_updated_idx ON published_artifacts(updated_at DESC)").run();
}

const TRIAL_DAYS = 7;
const TRIAL_TEXT_LIMIT = 40;
const TRIAL_IMAGE_LIMIT = 5;

async function ensureUsage(user, env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS feature_usage (
    user_id TEXT PRIMARY KEY,
    trial_started_at INTEGER NOT NULL,
    text_used INTEGER NOT NULL DEFAULT 0,
    images_used INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  )`).run();
  const now=Math.floor(Date.now()/1000);
  await env.DB.prepare("INSERT OR IGNORE INTO feature_usage(user_id,trial_started_at,text_used,images_used,updated_at) VALUES(?,?,0,0,?)").bind(user.id,now,now).run();
  return await env.DB.prepare("SELECT trial_started_at,text_used,images_used FROM feature_usage WHERE user_id=?").bind(user.id).first();
}
function entitlement(row) {
  const now=Math.floor(Date.now()/1000), expires=row.trial_started_at+TRIAL_DAYS*86400;
  const active=now<expires;
  return { plan:active?"free-trial":"trial-ended", trialActive:active, trialExpiresAt:expires,
    textLimit:TRIAL_TEXT_LIMIT, textUsed:Number(row.text_used||0), textRemaining:Math.max(0,TRIAL_TEXT_LIMIT-Number(row.text_used||0)),
    imageLimit:TRIAL_IMAGE_LIMIT, imagesUsed:Number(row.images_used||0), imagesRemaining:Math.max(0,TRIAL_IMAGE_LIMIT-Number(row.images_used||0)) };
}
async function reserveTrialUse(user,env,kind) {
  const row=await ensureUsage(user,env), info=entitlement(row);
  const col=kind==="image"?"images_used":"text_used", limit=kind==="image"?TRIAL_IMAGE_LIMIT:TRIAL_TEXT_LIMIT;
  if(!info.trialActive) return {ok:false,error:"Your 7-day free trial has ended.",info};
  const result=await env.DB.prepare(`UPDATE feature_usage SET ${col}=${col}+1,updated_at=? WHERE user_id=? AND ${col}<?`).bind(Math.floor(Date.now()/1000),user.id,limit).run();
  if(!result.meta?.changes) {
    const fresh=await ensureUsage(user,env);
    return {ok:false,error:kind==="image"?"You've used all 5 image generations in your free trial.":"You've used all 40 chat messages in your free trial.",info:entitlement(fresh)};
  }
  const fresh=await ensureUsage(user,env);
  return {ok:true,info:entitlement(fresh)};
}
async function refundTrialUse(user,env,kind) {
  const col=kind==="image"?"images_used":"text_used";
  await env.DB.prepare(`UPDATE feature_usage SET ${col}=MAX(0,${col}-1),updated_at=? WHERE user_id=?`).bind(Math.floor(Date.now()/1000),user.id).run();
}

const IMAGE_RATE = new Map();
function imageRateLimit(accountId) {
  // Rate-limit per Lightning account, not public IP. Friends on the same
  // school/home network should not consume one another's image allowance.
  const key = String(accountId || "unknown");
  const now = Date.now();
  const row = IMAGE_RATE.get(key);
  if (!row || now - row.start > 60000) {
    IMAGE_RATE.set(key, { start: now, count: 1 });
    if (IMAGE_RATE.size > 5000) {
      for (const [id, value] of IMAGE_RATE) if (now - value.start > 60000) IMAGE_RATE.delete(id);
    }
    return { ok: true };
  }
  if (row.count >= 5) return { ok: false, retryAfter: Math.max(1, Math.ceil((60000 - (now - row.start)) / 1000)) };
  row.count++;
  return { ok: true };
}
async function imageRoute(request, env) {
  if(!env.DB) return json({error:"Account database is not configured."},503);
  const account=await userFor(request,env);
  if(!account) return json({error:"Sign in to a Lightning account to use your free image trial."},401);

  if (!env.AI || typeof env.AI.run !== "function") {
    return json({ error: "Image generation is not enabled. Add the Workers AI binding named AI in Cloudflare." }, 503);
  }
  const limit = imageRateLimit(account.id);
  if (!limit.ok) return json({ error: "Too many images requested. Please wait a minute and try again.", retryAfter: limit.retryAfter }, 429, { "retry-after": String(limit.retryAfter) });
  let input;
  try { input = await body(request); } catch { return json({ error: "Invalid image request." }, 400); }
  let prompt = String(input.prompt || "").trim();
  if (!prompt) return json({ error: "Describe the image you want to create." }, 400);
  if (prompt.length > 1800) return json({ error: "Image prompts must be 1,800 characters or fewer." }, 400);
  const width = Math.max(256, Math.min(1536, Math.round(Number(input.width || 1024) / 16) * 16));
  const height = Math.max(256, Math.min(1536, Math.round(Number(input.height || 1024) / 16) * 16));
  const seed = Number.isInteger(Number(input.seed)) ? Math.abs(Number(input.seed)) % 2147483647 : Math.floor(Math.random() * 2147483647);
  const reserved=await reserveTrialUse(account,env,"image");
  if(!reserved.ok) return json({error:reserved.error,entitlement:reserved.info},403);
  if (input.enhance === true) {
    try {
      const improved = await env.AI.run("@cf/zai-org/glm-4.7-flash", {
        messages: [
          { role: "system", content: "You are an expert visual art director. Rewrite the user's idea as one precise, richly visual image-generation prompt. Preserve the subject and intent. Add concrete composition, camera/lens, lighting, environment, materials, colour palette and atmosphere where appropriate. Avoid contradictory details, text overlays and filler. Return only the improved prompt, under 180 words." },
          { role: "user", content: prompt }
        ],
        max_tokens: 240,
        temperature: 0.65
      });
      const candidate = improved?.response || improved?.choices?.[0]?.message?.content || improved?.output_text || "";
      if (typeof candidate === "string" && candidate.trim()) prompt = candidate.trim().slice(0, 1800);
    } catch (error) {
      // Prompt enhancement is optional; generation continues with the user's original prompt.
    }
  }
  try {
    // High-quality primary: FLUX.2 [dev]. Unlike Schnell/Klein, this
    // uses a full 25-step inference pass and respects the requested dimensions.
    // Cloudflare documents this model as its high-fidelity FLUX.2 option.
    try {
      const form = new FormData();
      form.append("prompt", prompt);
      form.append("width", String(width));
      form.append("height", String(height));
      form.append("seed", String(seed));
      form.append("steps", "25");
      form.append("guidance", "4");
      const encoded = new Response(form);
      const result = await env.AI.run("@cf/black-forest-labs/flux-2-dev", {
        multipart: { body: encoded.body, contentType: encoded.headers.get("content-type") }
      });
      if (typeof result?.image !== "string" || !result.image) {
        throw new Error("FLUX.2 Dev returned no image.");
      }
      return json({
        image: "data:image/png;base64," + result.image,
        entitlement: entitlement(await ensureUsage(account,env)),
        promptUsed: prompt,
        model: "FLUX.2 Dev · 25 steps",
        width,
        height,
        seed
      });
    } catch (qualityError) {
      console.warn("Lightning FLUX.2 Dev failed:", qualityError?.message || qualityError);
      // Lower-cost fallback if FLUX.2 Dev is unavailable.
      try {
        const form = new FormData();
        form.append("prompt", prompt);
        form.append("width", String(width));
        form.append("height", String(height));
        form.append("seed", String(seed));
        form.append("guidance", "4");
        const encoded = new Response(form);
        const backup = await env.AI.run("@cf/black-forest-labs/flux-2-klein-9b", {
          multipart: { body: encoded.body, contentType: encoded.headers.get("content-type") }
        });
        if (typeof backup?.image !== "string" || !backup.image) {
          throw new Error("FLUX.2 Klein 9B returned no image.");
        }
        return json({
          image: "data:image/png;base64," + backup.image,
          entitlement: entitlement(await ensureUsage(account,env)),
          promptUsed: prompt,
          model: "FLUX.2 Klein 9B (backup)",
          width,
          height,
          seed
        });
      } catch (backupError) {
        console.warn("Lightning FLUX.2 Klein 9B failed:", backupError?.message || backupError);
        // Last-resort compatibility fallback.
        const form = new FormData();
        form.append("prompt", prompt);
        form.append("width", String(width));
        form.append("height", String(height));
        form.append("seed", String(seed));
        form.append("guidance", "4");
        const encoded = new Response(form);
        const last = await env.AI.run("@cf/black-forest-labs/flux-2-klein-4b", {
          multipart: { body: encoded.body, contentType: encoded.headers.get("content-type") }
        });
        if (typeof last?.image !== "string" || !last.image) {
          throw new Error("All FLUX image models failed.");
        }
        return json({
          image: "data:image/png;base64," + last.image,
          entitlement: entitlement(await ensureUsage(account,env)),
          promptUsed: prompt,
          model: "FLUX.2 Klein 4B (last-resort backup)",
          width,
          height,
          seed
        });
      }
    }

  } catch (error) {
    const detail = String(error?.message || error || "Unknown Workers AI error");
    console.error("Lightning image generation failed on all FLUX models:", detail);
    // A failed Cloudflare inference must not consume the user's Lightning trial credit.
    try { await refundTrialUse(account,env,"image"); }
    catch (refundError) { console.error("Could not refund failed image trial use:", refundError?.message || refundError); }
    const quota = /4006|quota|daily.*(limit|allocation)|limit.*(reached|exceeded)|neuron|billing|payment|paid plan/i.test(detail);
    const capacity = /3040|capacity|overloaded|temporarily unavailable/i.test(detail);
    const status = quota ? 429 : 502;
    return json({
      error: quota
        ? "Cloudflare Workers AI has reached its free daily allowance. Your Lightning image credit has been returned. Try again after Cloudflare's daily reset."
        : capacity
          ? "Cloudflare's image models are currently out of capacity. Your Lightning image credit has been returned. Please try again shortly."
          : "Cloudflare's image models all failed. Your Lightning image credit has been returned. Check the Worker logs for the exact error, then try again."
    }, status);
  }
}


const VIDEO_RATE = new Map();
function videoRateLimit(request) {
  const ip=request.headers.get("CF-Connecting-IP")||"unknown", now=Date.now(), row=VIDEO_RATE.get(ip);
  if(!row||now-row.start>60000){VIDEO_RATE.set(ip,{start:now,count:1});return {ok:true};}
  if(row.count>=2)return {ok:false,retryAfter:Math.max(1,Math.ceil((60000-(now-row.start))/1000))};
  row.count++;return {ok:true};
}
async function generateRoute(request,env){
  if(!env.AI||typeof env.AI.run!=="function")return json({error:"Cloudflare Workers AI is not enabled for this deployment."},503);
  const limit=videoRateLimit(request);
  if(!limit.ok)return json({error:"Video generation is busy. Wait a minute before trying again.",retryAfter:limit.retryAfter},429,{"retry-after":String(limit.retryAfter)});
  let input;try{input=await body(request);}catch{return json({error:"Invalid generation request."},400);}
  const mode=String(input.mode||"text-to-video"),prompt=String(input.prompt||"").trim();
  if(!prompt)return json({error:"Enter a prompt describing the video."},400);
  if(prompt.length>1600)return json({error:"Prompts must be 1,600 characters or fewer."},400);
  if(mode==="image-to-image"){
    const data=String(input.imageData||"");
    if(!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(data))return json({error:"Choose a PNG, JPG or WebP image first."},400);
    if(data.length>11000000)return json({error:"The selected image is too large. Use an image under 8 MB."},413);
    try{
      const result=await env.AI.run("xai/grok-imagine-image",{prompt,image:{url:data},response_format:"url"});
      const image=result?.result?.image||result?.image;
      if(typeof image!=="string")return json({error:"The image model did not return an image. Try again."},502);
      return json({image,model:"Grok Imagine Image",mode});
    }catch(error){
      const detail=String(error?.message||error||"");
      const status=/quota|limit|neuron|billing|payment|credit|paid plan/i.test(detail)?429:502;
      return json({error:status===429?"Image editing is unavailable because the account's AI allowance or billing limit was reached.":"The image editing model is temporarily unavailable."},status);
    }
  }
  if(mode!=="text-to-video"&&mode!=="image-to-video")return json({error:"This generation mode is not connected yet."},400);
  const duration=Math.max(1,Math.min(15,Math.round(Number(input.duration)||5)));
  const resolution=input.resolution==="480p"?"480p":"720p";
  const ratios=["1:1","16:9","9:16","4:3","3:4","3:2","2:3"];
  const aspect_ratio=ratios.includes(input.aspect_ratio)?input.aspect_ratio:"16:9";
  const payload={prompt,duration,resolution,aspect_ratio};
  if(mode==="image-to-video"){
    const data=String(input.imageData||"");
    if(!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(data))return json({error:"Choose a PNG, JPG or WebP image first."},400);
    if(data.length>11000000)return json({error:"The selected image is too large. Use an image under 8 MB."},413);
    payload.image={url:data};
  }
  try{
    const result=await env.AI.run("xai/grok-imagine-video-1.5-preview",payload);
    const video=result?.result?.video||result?.video||result?.output?.video;
    if(typeof video!=="string"||!/^https:\/\//i.test(video))return json({error:"The video model did not return a playable video. Try again."},502);
    return json({video,model:"Grok Imagine Video 1.5",duration,resolution,aspect_ratio,mode});
  }catch(error){
    const detail=String(error?.message||error||"");
    const status=/quota|limit|neuron|billing|payment|credit|paid plan/i.test(detail)?429:502;
    return json({error:status===429?"Video generation is unavailable because the account's AI allowance or billing limit was reached. Check Cloudflare AI billing.":"The video model is temporarily unavailable. Please try again later."},status);
  }
}

const CHAT_RATE = new Map();
function chatRateLimit(request) {
  const ip=request.headers.get("CF-Connecting-IP")||"unknown", now=Date.now(), row=CHAT_RATE.get(ip);
  if(!row||now-row.start>60000){CHAT_RATE.set(ip,{start:now,count:1});return {ok:true};}
  if(row.count>=15)return {ok:false,retryAfter:Math.max(1,Math.ceil((60000-(now-row.start))/1000))};
  row.count++;return {ok:true};
}
async function chatRoute(request,env) {
  const limit=chatRateLimit(request);
  if(!limit.ok)return json({error:{message:"Lightning is receiving lots of free requests. Wait a moment and try again."}},429,{"retry-after":String(limit.retryAfter)});
  let input;try{input=await body(request);}catch{return json({error:{message:"Invalid chat request."}},400);}
  const messages=Array.isArray(input.messages)?input.messages.slice(-22):[];
  if(!messages.length)return json({error:{message:"Send a message first."}},400);
  const cleanMessages=messages.map(m=>({role:["system","user","assistant"].includes(m.role)?m.role:"user",content:typeof m.content==="string"?m.content:JSON.stringify(m.content)}));
  const max_tokens=Math.max(128,Math.min(4096,Number(input.max_tokens)||1800));
  const temperature=Math.max(0,Math.min(1.5,Number(input.temperature)||0.7));
  let cloudflareError="";
  if(env.AI&&typeof env.AI.run==="function") {
    try {
      const result=await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast",{messages:cleanMessages,max_tokens,temperature});
      const content=result?.response||result?.choices?.[0]?.message?.content||"";
      if(content)return json({choices:[{message:{role:"assistant",content}}],model:"Lightning Free · Llama 3.3"});
      cloudflareError="Cloudflare returned an empty answer.";
    } catch(error) { cloudflareError=String(error?.message||error||"Cloudflare AI unavailable."); }
  } else cloudflareError="Cloudflare Workers AI is not enabled.";
  // No external text fallback: Lightning chat uses Cloudflare AI only.
  return json({error:{message:"Lightning chat is temporarily unavailable because its Cloudflare AI model could not respond. Please try again shortly."}},503);
}

async function route(request, env) {
  const url=new URL(request.url), path=url.pathname;
  if(path.startsWith("/api/") && !sameOrigin(request)) return json({error:"Origin not allowed."},403);
  if(path==="/api/health" && request.method==="GET") return json({ok:true,service:"Lightning accounts"});
  if(path==="/api/health/db" && request.method==="GET") {
    if(!env.DB) return json({ok:false,stage:"binding",error:"D1 binding DB is missing."},503);
    try {
      await env.DB.prepare("SELECT 1 AS ok").first();
      await ensureAccountTables(env);
      const tables=await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','sessions','auth_attempts','user_data','shares') ORDER BY name").all();
      return json({ok:true,stage:"ready",tables:(tables.results||[]).map(row=>row.name)});
    } catch(error) {
      console.error("Lightning D1 diagnostic failed:",error?.stack||error);
      return json({ok:false,stage:"database",error:String(error?.message||error||"Unknown D1 error")},500);
    }
  }
  if(path==="/api/config" && request.method==="GET") return json({server:null});
  if(path==="/api/image" && request.method==="POST") return imageRoute(request, env);
  if(path==="/api/chat" && request.method==="POST") return chatRoute(request,env);
  if(path==="/api/generate" && request.method==="POST") return generateRoute(request, env);
  if(!env.DB) return json({error:"Account database is not configured yet."},503);
  if(!accountTablesReady) { try { await ensureAccountTables(env); accountTablesReady=true; } catch(error) { return json({error:"Lightning account database setup failed. Check the DB binding and D1 permissions.",detail:env.ENVIRONMENT==="development"?String(error):undefined},503); } }
  if(path==="/api/register" && request.method==="POST") {
    let b; try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    let stage="rate-limit";
    try {
      const limit=await authLimit(request,env);
      if(limit.blocked) return json({error:"Too many account attempts. Wait 15 minutes and try again."},429);
      const username=String(b.username||"").trim(), norm=username.toLowerCase(), password=String(b.password||"");
      if(!/^[A-Za-z0-9_]{3,24}$/.test(username)) return json({error:"Username must be 3–24 characters and use only letters, numbers or underscores."},400);
      if(password.length<10 || password.length>128) return json({error:"Password must be 10–128 characters."},400);
      stage="check-username";
      const exists=await env.DB.prepare("SELECT id FROM users WHERE username_norm=?").bind(norm).first();
      if(exists) {
        await env.DB.prepare("INSERT INTO auth_attempts(ip_hash,attempted_at) VALUES(?,?)").bind(limit.key,limit.now).run();
        return json({error:"That username is already taken."},409);
      }
      stage="hash-password";
      const id=b64(randomBytes(18)), salt=b64(randomBytes(16)), hash=await passwordHash(password,salt), now=Math.floor(Date.now()/1000);
      stage="insert-user";
      await env.DB.prepare("INSERT INTO users(id,username,username_norm,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)").bind(id,username,norm,salt,hash,now).run();
      stage="create-profile";
      await ensureProfile({id,username},env);
      stage="create-session";
      const user={id,username}, token=await newSession(user,env);
      return json({ok:true,user},201,{ "set-cookie":cookie(token,SESSION_DAYS*86400) });
    } catch(error) {
      console.error("Lightning registration failed at "+stage+":",error?.stack||error);
      return json({error:"Account registration failed.",stage,detail:String(error?.message||error||"Unknown error")},500);
    }
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
    await ensureProfile(row,env);
    const token=await newSession(row,env);
    return json({ok:true,user:{id:row.id,username:row.username}},200,{"set-cookie":cookie(token,SESSION_DAYS*86400)});
  }
  if(path==="/api/logout" && request.method==="POST") {
    const token=cookieValue(request,"lightning_session");
    if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha(token)).run();
    return json({ok:true},200,{"set-cookie":cookie("",0)});
  }
  const user=await userFor(request,env);
  if(path==="/api/me" && request.method==="GET") {
    if(!user)return json({user:null},401);
    const [usage,profile]=await Promise.all([ensureUsage(user,env),ensureProfile(user,env)]);
    return json({user:{...user,friendCode:profile.friend_code,avatar:profile.avatar_data||null},entitlement:entitlement(usage)});
  }
  if(path==="/api/profile" && request.method==="PUT") {
    if(!user)return json({error:"Sign in required."},401);
    let b;try{b=await body(request)}catch{return json({error:"Invalid profile update."},400)}
    const avatar=b.avatar===null?null:String(b.avatar||"");
    if(avatar && (!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(avatar)||avatar.length>100000))return json({error:"Profile images must be PNG, JPG or WebP and under 75 KB after compression."},413);
    await ensureProfile(user,env);
    await env.DB.prepare("UPDATE user_profiles SET avatar_data=?,updated_at=? WHERE user_id=?").bind(avatar||null,Math.floor(Date.now()/1000),user.id).run();
    return json({ok:true,avatar:avatar||null});
  }
  if(path==="/api/data" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    const row=await env.DB.prepare("SELECT data_json,updated_at FROM user_data WHERE user_id=?").bind(user.id).first();
    let data={};
    try { data=JSON.parse(row?.data_json||"{}"); } catch {}
    return json({data,updatedAt:row?.updated_at||null});
  }
  if(path==="/api/data" && request.method==="PUT") {
    if(!user)return json({error:"Sign in required."},401);
    let b;try{b=await body(request)}catch{return json({error:"Invalid or oversized data."},400)}
    const data=JSON.stringify(b.data??{});
    if(encoder.encode(data).length>MAX_DATA_BYTES)return json({error:"Your workspace is too large to save in one sync."},413);
    const now=Math.floor(Date.now()/1000);
    await env.DB.prepare("INSERT INTO user_data(user_id,data_json,object_key,updated_at) VALUES(?,?,NULL,?) ON CONFLICT(user_id) DO UPDATE SET data_json=excluded.data_json,object_key=NULL,updated_at=excluded.updated_at").bind(user.id,data,now).run();
    return json({ok:true});
  }
  if(path==="/api/users" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    await ensureProfile(user,env);
    const q=String(url.searchParams.get("q")||"").trim().slice(0,40);
    const rows=await env.DB.prepare(`SELECT users.id,users.username,
      user_profiles.avatar_data AS avatar,
      EXISTS(SELECT 1 FROM friendships WHERE (friendships.user_low=? AND friendships.user_high=users.id) OR (friendships.user_high=? AND friendships.user_low=users.id)) AS isFriend,
      EXISTS(SELECT 1 FROM friend_requests WHERE friend_requests.sender_id=? AND friend_requests.recipient_id=users.id AND friend_requests.status='pending') AS requestSent
      FROM users LEFT JOIN user_profiles ON user_profiles.user_id=users.id
      WHERE users.id<>? AND (?='' OR instr(lower(users.username),lower(?))>0)
      ORDER BY users.username COLLATE NOCASE LIMIT 50`).bind(user.id,user.id,user.id,user.id,q,q).all();
    return json({users:(rows.results||[]).map(u=>({username:u.username,avatar:u.avatar||null,isFriend:!!u.isFriend,requestSent:!!u.requestSent}))});
  }
  if(path==="/api/friends" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    const [friends,requests]=await Promise.all([
      env.DB.prepare("SELECT users.username,users.id,user_profiles.friend_code AS friendCode,user_profiles.avatar_data AS avatar FROM friendships JOIN users ON users.id=CASE WHEN friendships.user_low=? THEN friendships.user_high ELSE friendships.user_low END LEFT JOIN user_profiles ON user_profiles.user_id=users.id WHERE friendships.user_low=? OR friendships.user_high=? ORDER BY users.username").bind(user.id,user.id,user.id).all(),
      env.DB.prepare("SELECT friend_requests.id,users.username AS from_username,user_profiles.friend_code AS friendCode,user_profiles.avatar_data AS avatar FROM friend_requests JOIN users ON users.id=friend_requests.sender_id LEFT JOIN user_profiles ON user_profiles.user_id=users.id WHERE friend_requests.recipient_id=? AND friend_requests.status='pending' ORDER BY friend_requests.created_at DESC").bind(user.id).all()
    ]);
    return json({friends:friends.results||[],requests:requests.results||[]});
  }
  if(path==="/api/friends/messages" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    const lookup=String(url.searchParams.get("with")||"").trim();
    if(!lookup)return json({error:"Choose a friend to chat with."},400);
    const target=await env.DB.prepare("SELECT id,username FROM users WHERE username_norm=?").bind(lookup.toLowerCase()).first();
    if(!target)return json({error:"Friend not found."},404);
    const [low,high]=friendPair(user.id,target.id);
    const friendship=await env.DB.prepare("SELECT 1 AS ok FROM friendships WHERE user_low=? AND user_high=?").bind(low,high).first();
    if(!friendship)return json({error:"You can only message accepted friends."},403);
    const rows=await env.DB.prepare("SELECT direct_messages.id,direct_messages.sender_id,direct_messages.message,direct_messages.created_at,users.username AS sender_name FROM direct_messages JOIN users ON users.id=direct_messages.sender_id WHERE (direct_messages.sender_id=? AND direct_messages.recipient_id=?) OR (direct_messages.sender_id=? AND direct_messages.recipient_id=?) ORDER BY direct_messages.created_at ASC LIMIT 200").bind(user.id,target.id,target.id,user.id).all();
    return json({messages:(rows.results||[]).map(m=>({id:m.id,from:m.sender_name,message:m.message,createdAt:m.created_at,mine:m.sender_id===user.id}))});
  }
  if(path==="/api/friends/messages" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    let b;try{b=await body(request)}catch{return json({error:"Invalid message."},400)}
    const lookup=String(b.friend||"").trim(),message=String(b.message||"").trim();
    if(!lookup||!message)return json({error:"Choose a friend and enter a message."},400);
    if(message.length>2000)return json({error:"Messages are limited to 2,000 characters."},413);
    const target=await env.DB.prepare("SELECT id FROM users WHERE username_norm=?").bind(lookup.toLowerCase()).first();
    if(!target)return json({error:"Friend not found."},404);
    const [low,high]=friendPair(user.id,target.id);
    const friendship=await env.DB.prepare("SELECT 1 AS ok FROM friendships WHERE user_low=? AND user_high=?").bind(low,high).first();
    if(!friendship)return json({error:"You can only message accepted friends."},403);
    const id=b64(randomBytes(18)),now=Math.floor(Date.now()/1000);
    await env.DB.prepare("INSERT INTO direct_messages(id,sender_id,recipient_id,message,created_at) VALUES(?,?,?,?,?)").bind(id,user.id,target.id,message,now).run();
    return json({ok:true,id,createdAt:now});
  }
  if(path==="/api/friends/request" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const lookup=String(b.key||b.username||b.friendCode||"").trim();
    if(!lookup)return json({error:"Enter a Lightning friend key or username."},400);
    const target=await env.DB.prepare("SELECT users.id,users.username FROM users LEFT JOIN user_profiles ON user_profiles.user_id=users.id WHERE users.username_norm=? OR user_profiles.friend_code=?").bind(lookup.toLowerCase(),lookup.toUpperCase()).first();
    if(!target)return json({error:"No Lightning account found with that key or username."},404);
    if(target.id===user.id)return json({error:"You cannot add yourself."},400);
    const [low,high]=friendPair(user.id,target.id);
    const existing=await env.DB.prepare("SELECT 1 AS ok FROM friendships WHERE user_low=? AND user_high=?").bind(low,high).first();
    if(existing)return json({error:"You are already friends."},409);
    const reverse=await env.DB.prepare("SELECT id FROM friend_requests WHERE sender_id=? AND recipient_id=? AND status='pending'").bind(target.id,user.id).first();
    if(reverse){
      await env.DB.prepare("INSERT OR IGNORE INTO friendships(user_low,user_high,created_at) VALUES(?,?,?)").bind(low,high,Math.floor(Date.now()/1000)).run();
      await env.DB.prepare("UPDATE friend_requests SET status='accepted' WHERE id=?").bind(reverse.id).run();
      return json({ok:true,accepted:true,username:target.username});
    }
    const pending=await env.DB.prepare("SELECT id,status FROM friend_requests WHERE sender_id=? AND recipient_id=?").bind(user.id,target.id).first();
    if(pending?.status==="pending")return json({ok:true,pending:true,username:target.username});
    if(pending) {
      await env.DB.prepare("UPDATE friend_requests SET status='pending',created_at=? WHERE id=?").bind(Math.floor(Date.now()/1000),pending.id).run();
    } else {
      const id=b64(randomBytes(18));
      await env.DB.prepare("INSERT INTO friend_requests(id,sender_id,recipient_id,status,created_at) VALUES(?,?,?,'pending',?)").bind(id,user.id,target.id,Math.floor(Date.now()/1000)).run();
    }
    return json({ok:true,pending:true,username:target.username});
  }
  if(path==="/api/friends/respond" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const id=String(b.id||""),action=String(b.action||"");
    const req=await env.DB.prepare("SELECT id,sender_id,recipient_id FROM friend_requests WHERE id=? AND recipient_id=? AND status='pending'").bind(id,user.id).first();
    if(!req)return json({error:"Friend request not found."},404);
    if(action==="accept"){
      const [low,high]=friendPair(req.sender_id,req.recipient_id);
      await env.DB.prepare("INSERT OR IGNORE INTO friendships(user_low,user_high,created_at) VALUES(?,?,?)").bind(low,high,Math.floor(Date.now()/1000)).run();
      await env.DB.prepare("UPDATE friend_requests SET status='accepted' WHERE id=?").bind(id).run();
    }else if(action==="decline"){
      await env.DB.prepare("UPDATE friend_requests SET status='declined' WHERE id=?").bind(id).run();
    }else return json({error:"Choose accept or decline."},400);
    return json({ok:true});
  }
  if(path==="/api/share" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const target=String(b.key||b.username||b.friendCode||"").trim(), artifact=JSON.stringify(b.artifact??{});
    if(!target)return json({error:"Enter a Lightning friend key or username."},400);
    if(encoder.encode(artifact).length>1000000)return json({error:"That creation is too large to share (1 MB maximum). Images are automatically compressed before sharing."},413);
    const recipient=await env.DB.prepare("SELECT users.id FROM users LEFT JOIN user_profiles ON user_profiles.user_id=users.id WHERE users.username_norm=? OR user_profiles.friend_code=?").bind(target.toLowerCase(),target.toUpperCase()).first();
    if(!recipient)return json({error:"No Lightning account found with that key or username."},404);
    if(recipient.id===user.id)return json({error:"You cannot share an artefact with yourself."},400);
    await ensureSocialTables(env);
    const [low,high]=friendPair(user.id,recipient.id);
    const friendship=await env.DB.prepare("SELECT 1 AS ok FROM friendships WHERE user_low=? AND user_high=?").bind(low,high).first();
    if(!friendship)return json({error:"Add this person as a Lightning friend before sharing."},403);
    const id=b64(randomBytes(18));
    await env.DB.prepare("INSERT INTO shares(id,owner_id,recipient_id,artifact_json,created_at) VALUES(?,?,?,?,?)").bind(id,user.id,recipient.id,artifact,Math.floor(Date.now()/1000)).run();
    return json({ok:true,shareId:id});
  }
  if(path==="/api/shares" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    const rows=await env.DB.prepare("SELECT shares.id, shares.artifact_json, shares.created_at, users.username AS from_username FROM shares JOIN users ON users.id=shares.owner_id WHERE shares.recipient_id=? ORDER BY shares.created_at DESC LIMIT 100").bind(user.id).all();
    return json({shares:(rows.results||[]).map(row=>{let artifact={};try{artifact=JSON.parse(row.artifact_json)}catch{}return {id:row.id,from:row.from_username,title:artifact.title||"Shared creation",kind:artifact.kind==="image"?"image":"artifact",createdAt:row.created_at};})});
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
  if(path==="/api/artifacts" && request.method==="GET") {
    await ensurePublishedTable(env);
    const id=String(url.searchParams.get("id")||"").trim();
    if(id){
      const row=await env.DB.prepare("SELECT id,title,code,created_at,updated_at FROM published_artifacts WHERE id=?").bind(id).first();
      if(!row)return json({error:"Online artifact not found."},404);
      return json({id:row.id,title:row.title,code:row.code,t:row.created_at,updatedAt:row.updated_at});
    }
    const rows=await env.DB.prepare("SELECT id,title,created_at,owner_id FROM published_artifacts ORDER BY updated_at DESC LIMIT 200").all();
    return json({items:(rows.results||[]).map(row=>({id:row.id,title:row.title,t:row.created_at,owner:!!user&&row.owner_id===user.id}))});
  }
  if(path==="/api/artifacts" && (request.method==="POST" || request.method==="PUT")) {
    if(!user)return json({error:"Sign in to publish an artifact."},401);
    await ensurePublishedTable(env);
    let b;try{b=await body(request)}catch{return json({error:"Invalid or oversized artifact."},400)}
    const title=String(b.title||"Untitled artifact").trim().slice(0,100)||"Untitled artifact";
    const code=String(b.code||"");
    if(!code.trim())return json({error:"The artifact is empty."},400);
    if(encoder.encode(code).length>1000000)return json({error:"This artifact is too large to publish (1 MB maximum)."},413);
    const now=Math.floor(Date.now()/1000);
    if(request.method==="PUT"){
      const id=String(b.id||"").trim();
      if(!id)return json({error:"Missing artifact ID."},400);
      const existing=await env.DB.prepare("SELECT id FROM published_artifacts WHERE id=? AND owner_id=?").bind(id,user.id).first();
      if(!existing)return json({error:"Your published artifact was not found."},404);
      await env.DB.prepare("UPDATE published_artifacts SET title=?,code=?,updated_at=? WHERE id=? AND owner_id=?").bind(title,code,now,id,user.id).run();
      return json({ok:true,id,url:new URL("/a/"+encodeURIComponent(id),request.url).toString(),updated:true});
    }
    const id=b64(randomBytes(12));
    await env.DB.prepare("INSERT INTO published_artifacts(id,owner_id,title,code,created_at,updated_at) VALUES(?,?,?,?,?,?)").bind(id,user.id,title,code,now,now).run();
    return json({ok:true,id,url:new URL("/a/"+encodeURIComponent(id),request.url).toString()},201);
  }
  if(path==="/api/artifacts" && request.method==="DELETE") {
    if(!user)return json({error:"Sign in to delete your published artifact."},401);
    await ensurePublishedTable(env);
    const id=String(url.searchParams.get("id")||"").trim();
    if(!id)return json({error:"Missing artifact ID."},400);
    const result=await env.DB.prepare("DELETE FROM published_artifacts WHERE id=? AND owner_id=?").bind(id,user.id).run();
    if(!result.meta?.changes)return json({error:"Your published artifact was not found."},404);
    return json({ok:true});
  }
  if(path.startsWith("/a/") && request.method==="GET") {
    await ensurePublishedTable(env);
    const id=decodeURIComponent(path.slice(3));
    const row=await env.DB.prepare("SELECT title,code FROM published_artifacts WHERE id=?").bind(id).first();
    if(!row)return new Response("Online artifact not found.",{status:404,headers:{"content-type":"text/plain; charset=utf-8","cache-control":"no-store"}});
    const csp="sandbox allow-scripts allow-forms allow-modals; default-src 'none'; script-src 'unsafe-inline' https:; style-src 'unsafe-inline' https:; img-src data: blob: https:; font-src data: https:; media-src data: blob: https:; connect-src 'none'; base-uri 'none'; form-action 'none'";
    return new Response(row.code,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"public, max-age=60","content-security-policy":csp,"x-content-type-options":"nosniff","referrer-policy":"no-referrer"}});
  }
  return env.ASSETS.fetch(request);
}
export default {
  async fetch(request, env, ctx) {
    try { return await route(request,env); }
    catch(e) {
      console.error("Lightning Worker request failed:", e?.stack || e);
      return json({error:"Server error. Please try again.",detail:env.ENVIRONMENT==="development"?String(e):undefined},500);
    }
  }
};
