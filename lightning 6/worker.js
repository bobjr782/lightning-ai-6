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


async function ensureModerationTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS moderation_consents (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    accepted_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS chat_conversations (
    id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT 'New chat',
    messages_json TEXT NOT NULL,
    flagged_terms_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(user_id,id)
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS chat_conversations_flagged_idx ON chat_conversations(updated_at DESC)").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS blocked_users (
    username_norm TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    blocked_at INTEGER NOT NULL
  )`).run();
}
const PROFANITY_TERMS = ["fuck","fucking","fucked","shit","bullshit","bitch","bastard","asshole","arsehole","cunt","dickhead","motherfucker","piss off","crap"];
function findProfanity(messages) {
  const textValue=(Array.isArray(messages)?messages:[]).map(m=>[m?.text,m?.content,m?.message].filter(x=>typeof x==="string").join(" ")).join(" ").toLowerCase();
  const normalized=" "+textValue.replace(/[^a-z0-9]+/g," ")+" ";
  return PROFANITY_TERMS.filter(term=>normalized.includes(" "+term+" "));
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
async function pollinationsImage(prompt,width,height,seed,env) {
  const key=env.POLLINATIONS_API_KEY;
  if(!key) return null;
  const response=await fetch("https://gen.pollinations.ai/v1/images/generations",{
    method:"POST",
    headers:{
      "Authorization":"Bearer "+key,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      model:"black-forest-labs/flux.1-schnell",
      prompt,
      size:`${width}x${height}`,
      seed,
      response_format:"b64_json"
    })
  });
  if(!response.ok) {
    const detail=await response.text().catch(()=>"");
    throw new Error("Pollinations image API returned HTTP "+response.status+": "+detail.slice(0,500));
  }
  const data=await response.json();
  const image=data?.data?.[0]?.b64_json;
  if(typeof image!=="string"||!image) throw new Error("Pollinations did not return a base64 image.");
  return image;
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
    console.error("Lightning Workers AI image models failed:", detail);
    // If Cloudflare is out of capacity/quota, use the separately configured provider.
    if(env.POLLINATIONS_API_KEY) {
      try {
        const image=await pollinationsImage(prompt,width,height,seed,env);
        return json({
          image:"data:image/png;base64,"+image,
          entitlement:entitlement(await ensureUsage(account,env)),
          promptUsed:prompt,
          model:"Pollinations · FLUX.1 Schnell (backup)",
          width,height,seed
        });
      } catch(fallbackError) {
        console.error("Lightning Pollinations image fallback failed:",fallbackError?.message||fallbackError);
      }
    }
    // Neither provider produced an image: return the trial credit.
    try { await refundTrialUse(account,env,"image"); }
    catch (refundError) { console.error("Could not refund failed image trial use:", refundError?.message || refundError); }
    const quota = /4006|quota|daily.*(limit|allocation)|limit.*(reached|exceeded)|neuron|billing|payment|paid plan/i.test(detail);
    const capacity = /3040|capacity|overloaded|temporarily unavailable/i.test(detail);
    const status = quota ? 429 : 502;
    return json({
      error: env.POLLINATIONS_API_KEY
        ? "Cloudflare and the backup image provider both failed. Your Lightning image credit has been returned. Check Worker logs for details."
        : quota
          ? "Cloudflare Workers AI has reached its free daily allowance. Your Lightning image credit has been returned. Add a POLLINATIONS_API_KEY Worker secret to enable the backup image provider."
          : capacity
            ? "Cloudflare's image models are currently out of capacity. Your Lightning image credit has been returned. Add a POLLINATIONS_API_KEY Worker secret to enable backup generation."
            : "Cloudflare's image models all failed. Your Lightning image credit has been returned. Check the Worker logs for the exact error."
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

async function openverseImageReferences(prompt,count) {
  const params=new URLSearchParams({q:prompt,page_size:String(Math.min(20,count)),mature:"false"});
  const response=await fetch("https://api.openverse.org/v1/images/?"+params.toString(),{
    headers:{"Accept":"application/json","User-Agent":"LightningImageForge/1.0"}
  });
  if(!response.ok) throw new Error("Openverse image library returned HTTP "+response.status);
  const data=await response.json();
  return (data?.results||[]).map(item=>{
    const url=String(item.url||item.thumbnail||"");
    if(!/^https:\/\//i.test(url))return null;
    return {
      title:String(item.title||"Untitled image").slice(0,180),
      url,
      source:String(item.foreign_landing_url||item.detail_url||""),
      width:item.width||null,
      height:item.height||null,
      license:String(item.license||"").slice(0,80),
      licenseUrl:String(item.license_url||""),
      artist:String(item.creator||"").slice(0,180)
    };
  }).filter(Boolean);
}

const IMAGE_REFERENCE_RATE = new Map();
async function imageReferencesRoute(request,env) {
  if(!env.DB) return json({error:"Account database is not configured."},503);
  const account=await userFor(request,env);
  if(!account) return json({error:"Sign in to Lightning before searching for image references."},401);
  const now=Date.now(), prior=IMAGE_REFERENCE_RATE.get(account.id);
  if(prior&&now-prior<15000) return json({error:"Please wait a few seconds before searching again."},429,{"retry-after":"15"});
  IMAGE_REFERENCE_RATE.set(account.id,now);
  let input; try{input=await body(request);}catch{return json({error:"Invalid image search request."},400);}
  const rawPrompt=String(input.prompt||"").trim().slice(0,240);
  const noBackground=/#no-background\s*$/i.test(rawPrompt);
  const prompt=rawPrompt.replace(/\s*#no-background\s*$/i,"").trim();
  const searchPrompt=noBackground?prompt+" transparent background PNG":prompt;
  const requestedCount=Number(input.count||20);
  const count=Number.isFinite(requestedCount)?Math.max(8,Math.min(20,Math.round(requestedCount))):20;
  if(prompt.length<2) return json({error:"Describe what images you want to find."},400);
  try{
    // Search Google Images directly. No chatbot or intermediate AI prompt is involved.
    // Rotate through Google Images result pages so repeat searches do not
    // always return the same first-page thumbnails. A short random page offset
    // also varies the result set between requests.
    const pageStart=Math.floor(Math.random()*4);
    const searchUrl="https://www.google.com/search?tbm=isch&udm=2&hl=en&safe=active"+(noBackground?"&tbs=ic:trans":"")+"&q="+encodeURIComponent(searchPrompt)+"&ijn="+pageStart;
    const found=[];
    const addUrl=value=>{
      if(!value)return;
      let url=String(value).replace(/\\u003d/g,"=").replace(/\\u0026/g,"&").replace(/\\u003c/g,"<").replace(/\\u003e/g,">").replace(/\\\\\\//g,"/");
      try{url=decodeURIComponent(url);}catch(_){}
      url=url.replace(/&amp;/g,"&").replace(/\\u0026/g,"&");
      if(!/^https:\/\//i.test(url))return;
      if(/(^|\.)google\.(com|com\.au)$|gstatic\.com|googleusercontent\.com/i.test(new URL(url).hostname))return;
      if(!/\.(jpe?g|png|webp|gif|avif)(?:$|[?#])/i.test(url))return;
      if(!found.includes(url))found.push(url);
    };
    // Fetch two neighbouring result pages, not just Google's default first page.
    for(let page=pageStart;page<pageStart+2&&found.length<count*3;page++){
      const pageUrl="https://www.google.com/search?tbm=isch&udm=2&hl=en&safe=active"+(noBackground?"&tbs=ic:trans":"")+"&q="+encodeURIComponent(searchPrompt)+"&ijn="+page;
      const response=await fetch(pageUrl,{headers:{
        "Accept":"text/html,application/xhtml+xml",
        "Accept-Language":"en-AU,en;q=0.9",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
      },redirect:"follow"});
      if(!response.ok)throw new Error("Google Images returned HTTP "+response.status+". Google may be blocking automated searches.");
      const html=await response.text();
      if(/unusual traffic|sorry\/|consent\.google\.com|before you continue to google/i.test(html.slice(0,180000)))
        throw new Error("Google showed a verification or consent page instead of image results.");
      let match;
      const originalPattern=/"ou"\s*:\s*"([^"]+)"/g;
      while((match=originalPattern.exec(html))&&found.length<count*3){
        try{addUrl(JSON.parse('"'+match[1]+'"'));}catch(_){addUrl(match[1]);}
      }
      const encodedPattern=/imgurl=(https?%3A%2F%2F[^&"\s]+)/gi;
      while((match=encodedPattern.exec(html))&&found.length<count*3)addUrl(match[1]);
      const plainPattern=/imgurl=(https?:\/\/[^&"\s]+)/gi;
      while((match=plainPattern.exec(html))&&found.length<count*3)addUrl(match[1]);
    }
    const results=found.slice(0,count).map((url,index)=>({
      title:"Google Images result "+(index+1),
      url,
      source:searchUrl,
      license:"Check original source for usage rights",
      artist:""
    }));
    let source="Google Images";
    if(results.length<count && !noBackground){
      try{
        const libraryResults=await openverseImageReferences(searchPrompt,count-results.length);
        const seen=new Set(results.map(item=>item.url));
        for(const item of libraryResults){
          if(results.length>=count)break;
          if(!seen.has(item.url)){seen.add(item.url);results.push(item);}
        }
        if(results.some(item=>item.licenseUrl))source="Google Images + Openverse";
      }catch(libraryError){
        console.warn("Openverse top-up unavailable:",libraryError?.message||libraryError);
      }
    }
    return json({ok:true,query:prompt,searchQuery:searchPrompt,noBackground,source,count:results.length,requested:count,results,searchUrl});
  }catch(error){
    console.warn("Google Images unavailable; trying Openverse:",error?.message||error);
    if(noBackground){
      return json({error:"Google could not verify transparent-image results right now. No unverified images were substituted. Please try again later."},502);
    }
    try{
      const results=await openverseImageReferences(searchPrompt,count);
      return json({ok:true,query:prompt,searchQuery:searchPrompt,noBackground,source:"Openverse image library",count:results.length,requested:count,results,fallback:true});
    }catch(libraryError){
      console.error("Both image sources failed:",error?.message||error,libraryError?.message||libraryError);
      return json({error:"Google Images and the Openverse image library are temporarily unavailable. "+String(libraryError?.message||error?.message||"Try again later.")},502);
    }
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

  // Guest/no-personal-key default: JarvisClaw's free-only router.
  // The secret stays on the Worker and is never sent to browser code.
  let jarvisError="";
  if(env.JARVISCLAW_API_KEY) {
    try {
      const response=await fetch("https://api.jarvisclaw.ai/v1/chat/completions",{
        method:"POST",
        headers:{
          "Authorization":"Bearer "+env.JARVISCLAW_API_KEY,
          "Content-Type":"application/json",
          "Accept":"application/json"
        },
        body:JSON.stringify({
          model:"auto/free",
          messages:cleanMessages,
          max_tokens,
          temperature,
          stream:false
        }),
        signal:AbortSignal.timeout(55000)
      });
      const data=await response.json().catch(()=>null);
      const content=data?.choices?.[0]?.message?.content;
      if(response.ok && typeof content==="string" && content.trim()) {
        return json({
          choices:[{message:{role:"assistant",content}}],
          model:data.model||"JarvisClaw · Auto Free",
          provider:"jarvisclaw"
        });
      }
      jarvisError=data?.error?.message||data?.message||("JarvisClaw returned HTTP "+response.status);
      console.warn("Lightning JarvisClaw request failed:",jarvisError);
    } catch(error) {
      jarvisError=String(error?.message||error||"JarvisClaw unavailable.");
      console.warn("Lightning JarvisClaw request failed:",jarvisError);
    }
  } else {
    jarvisError="JarvisClaw is not configured. Add the JARVISCLAW_API_KEY Worker secret.";
  }

  // Keep the existing Cloudflare model as a backup if JarvisClaw is down,
  // rate-limited, or the free model pool is temporarily unavailable.
  if(env.AI&&typeof env.AI.run==="function") {
    try {
      const result=await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast",{messages:cleanMessages,max_tokens,temperature});
      const content=result?.response||result?.choices?.[0]?.message?.content||"";
      if(content)return json({
        choices:[{message:{role:"assistant",content}}],
        model:"Lightning Backup · Llama 3.3",
        provider:"cloudflare"
      });
    } catch(error) {
      console.warn("Lightning Cloudflare chat backup failed:",String(error?.message||error||""));
    }
  }
  return json({error:{message:env.JARVISCLAW_API_KEY
    ?"Lightning's free AI providers are temporarily unavailable. Please try again shortly."
    :"Lightning's free AI is not configured yet. The site owner needs to add the JARVISCLAW_API_KEY secret in Cloudflare."}},503);
}


async function ensureBrowserTable(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS browser_sessions (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, session_id TEXT NOT NULL, target_id TEXT NOT NULL, paused INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)").run();
}
function browserSafeUrl(value) {
  let u;
  try { u = new URL(String(value || "")); } catch { throw new Error("Enter a valid website URL."); }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("Only HTTP and HTTPS websites are allowed.");
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0" || host.endsWith(".local")) throw new Error("Local and private network addresses are not allowed.");
  return u.toString();
}
let browserCdpId = 0;
function browserCdp(socket, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++browserCdpId;
    const timeout = setTimeout(() => { cleanup(); reject(new Error("Browser command timed out: " + method)); }, 20000);
    const cleanup = () => { clearTimeout(timeout); socket.removeEventListener("message", onMessage); socket.removeEventListener("close", onClose); };
    const onClose = () => { cleanup(); reject(new Error("Browser connection closed.")); };
    const onMessage = event => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.id !== id) return;
      cleanup();
      if (message.error) reject(new Error(message.error.message || "Browser command failed."));
      else resolve(message.result || {});
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
    try { socket.send(JSON.stringify({ id, method, params })); }
    catch (error) { cleanup(); reject(error); }
  });
}
async function withBrowserSocket(env, sessionId, targetId, callback) {
  const connection = await env.BROWSER.connectSession(sessionId, { targetId });
  const response = await connection.webSocket.fetch("https://browser-binding.invalid", { headers: { Upgrade: "websocket" } });
  if (!response.webSocket) throw new Error("Cloudflare did not open the browser connection.");
  const socket = response.webSocket;
  socket.accept();
  try { return await callback(socket); }
  finally { try { socket.close(); } catch {} }
}
async function browserPageInfo(socket) {
  const result = await browserCdp(socket, "Runtime.evaluate", {
    expression: "({title:document.title,url:location.href,text:(document.body&&document.body.innerText||'').slice(0,12000)})",
    returnByValue: true,
    awaitPromise: true
  });
  return result.result && result.result.value || {};
}
function browserCaptchaDetected(info) {
  const sample = ((info.title || "") + " " + (info.url || "") + " " + (info.text || "")).toLowerCase();
  return /captcha|verify (that )?you are human|checking your browser|security challenge|unusual traffic|are you a robot|robot check|challenge-platform|hcaptcha|recaptcha|cf-turnstile|just a moment/.test(sample);
}
async function browserStartRoute(request, env) {
  const user = await userFor(request, env);
  if (!user) return json({ error: "Sign in to use Lightning Browser." }, 401);
  if (!env.BROWSER) return json({ error: "Cloudflare Browser Run is not enabled on this Worker yet. Add the BROWSER browser binding in Wrangler and enable Browser Run in Cloudflare." }, 503);
  await ensureBrowserTable(env);
  let data;
  try { data = await body(request); } catch { return json({ error: "Invalid browser request." }, 400); }
  let targetUrl;
  try { targetUrl = browserSafeUrl(data.url || "https://scratch.mit.edu/"); }
  catch (error) { return json({ error: error.message }, 400); }
  const old = await env.DB.prepare("SELECT session_id FROM browser_sessions WHERE user_id=?").bind(user.id).first();
  if (old?.session_id) { try { await env.BROWSER.closeSession(old.session_id); } catch {} }
  let session;
  try {
    session = await env.BROWSER.acquire({ targets: true, keepAlive: 1200000, liveViewUrlExpiresInMs: 3600000 });
    let target = (session.targets || []).find(item => item.type === "page");
    if (!target) target = await env.BROWSER.devtools.newTarget(session.sessionId, "about:blank");
    await withBrowserSocket(env, session.sessionId, target.id, async socket => {
      await browserCdp(socket, "Page.enable");
      await browserCdp(socket, "Runtime.enable");
      await browserCdp(socket, "Emulation.setDeviceMetricsOverride", { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false });
      await browserCdp(socket, "Page.navigate", { url: targetUrl });
    });
    const live = await env.BROWSER.getLiveView(session.sessionId, { targetId: target.id, mode: "tab", expiresInMs: 3600000 });
    await env.DB.prepare("INSERT OR REPLACE INTO browser_sessions(user_id,session_id,target_id,paused,created_at) VALUES(?,?,?,0,?)")
      .bind(user.id, session.sessionId, target.id, Math.floor(Date.now()/1000)).run();
    return json({ ok: true, liveViewUrl: live.devtoolsFrontendUrl, url: targetUrl, title: "Lightning Browser" });
  } catch (error) {
    if (session?.sessionId) { try { await env.BROWSER.closeSession(session.sessionId); } catch {} }
    console.error("Lightning Browser start failed:", error?.stack || error);
    return json({ error: String(error?.message || error || "Browser could not start.") }, 503);
  }
}
async function browserCommandRoute(request, env) {
  const user = await userFor(request, env);
  if (!user) return json({ error: "Sign in to use Lightning Browser." }, 401);
  if (!env.BROWSER) return json({ error: "Cloudflare Browser Run is not enabled." }, 503);
  await ensureBrowserTable(env);
  let data;
  try { data = await body(request); } catch { return json({ error: "Invalid browser command." }, 400); }
  const row = await env.DB.prepare("SELECT session_id,target_id,paused FROM browser_sessions WHERE user_id=?").bind(user.id).first();
  if (!row) return json({ error: "No browser session is open. Start the browser first." }, 404);
  const command = String(data.command || "");
  if (command !== "CAPTCHA" && command !== "screenshot" && Number(row.paused)) return json({ error: "Browser automation is paused for human verification. Complete the challenge and press Resume." }, 423);
  try {
    if (command === "CAPTCHA") {
      const info = await withBrowserSocket(env,row.session_id,row.target_id,socket => browserPageInfo(socket));
      const detected = browserCaptchaDetected(info);
      if (detected) await env.DB.prepare("UPDATE browser_sessions SET paused=1 WHERE user_id=?").bind(user.id).run();
      return json({ ok: true, detected, paused: detected, page: { title: info.title || "", url: info.url || "" }, message: detected ? "Verification detected. Please complete it in the browser, then press Resume." : "No CAPTCHA detected." });
    }
    if (command === "navigate") {
      let targetUrl;
      try { targetUrl = browserSafeUrl(data.url); } catch (error) { return json({ error: error.message }, 400); }
      await withBrowserSocket(env,row.session_id,row.target_id,socket => browserCdp(socket,"Page.navigate",{url:targetUrl}));
      return json({ ok:true, url:targetUrl });
    }
    if (command === "reload") {
      await withBrowserSocket(env,row.session_id,row.target_id,socket => browserCdp(socket,"Page.reload",{ignoreCache:false}));
      return json({ok:true});
    }
    if (command === "back" || command === "forward") {
      const result = await withBrowserSocket(env,row.session_id,row.target_id,async socket => {
        const history = await browserCdp(socket,"Page.getNavigationHistory");
        const offset = command === "back" ? -1 : 1;
        const entry = (history.entries || [])[Number(history.currentIndex) + offset];
        if (!entry) return { moved:false };
        await browserCdp(socket,"Page.navigateToHistoryEntry",{entryId:entry.id});
        return { moved:true, url:entry.url };
      });
      return json({ok:true,...result});
    }
    if (command === "stop-loading") {
      await withBrowserSocket(env,row.session_id,row.target_id,socket => browserCdp(socket,"Page.stopLoading"));
      return json({ok:true});
    }
    if (command === "simulate") {
      const action = String(data.action || "");
      const x = Math.max(0,Math.min(5000,Number(data.x)||0));
      const y = Math.max(0,Math.min(5000,Number(data.y)||0));
      await withBrowserSocket(env,row.session_id,row.target_id,async socket => {
        if (action === "move") {
          await browserCdp(socket,"Input.dispatchMouseEvent",{type:"mouseMoved",x,y});
        } else if (action === "click") {
          await browserCdp(socket,"Input.dispatchMouseEvent",{type:"mouseMoved",x,y});
          await browserCdp(socket,"Input.dispatchMouseEvent",{type:"mousePressed",x,y,button:"left",clickCount:1});
          await browserCdp(socket,"Input.dispatchMouseEvent",{type:"mouseReleased",x,y,button:"left",clickCount:1});
        } else if (action === "type") {
          const value = String(data.text || "").slice(0,2000);
          await browserCdp(socket,"Input.insertText",{text:value});
        } else if (action === "scroll") {
          const deltaY = Math.max(-3000,Math.min(3000,Number(data.amount)||500));
          await browserCdp(socket,"Input.dispatchMouseEvent",{type:"mouseWheel",x:x||640,y:y||360,deltaX:0,deltaY});
        } else if (action === "press") {
          const key = String(data.key || "").slice(0,30);
          if (!/^(Enter|Tab|Escape|Backspace|Arrow(Up|Down|Left|Right)|Space)$/.test(key)) throw new Error("Unsupported key.");
          const keyValue = key === "Space" ? " " : key;
          await browserCdp(socket,"Input.dispatchKeyEvent",{type:"keyDown",key:keyValue,code:key==="Space"?"Space":key});
          await browserCdp(socket,"Input.dispatchKeyEvent",{type:"keyUp",key:keyValue,code:key==="Space"?"Space":key});
        } else throw new Error("Unknown simulate action.");
      });
      return json({ok:true,action,x,y});
    }
    if (command === "screenshot") {
      const result = await withBrowserSocket(env,row.session_id,row.target_id,socket => browserCdp(socket,"Page.captureScreenshot",{format:"jpeg",quality:75,fromSurface:true}));
      return json({ok:true,dataUrl:"data:image/jpeg;base64,"+result.data});
    }
    if (command === "readPage") {
      const info = await withBrowserSocket(env,row.session_id,row.target_id,socket => browserPageInfo(socket));
      return json({ok:true,page:info});
    }
    return json({error:"Unknown browser command."},400);
  } catch (error) {
    console.error("Lightning Browser command failed:",error?.stack||error);
    return json({error:String(error?.message||error||"Browser command failed.")},500);
  }
}
async function browserResumeRoute(request, env) {
  const user = await userFor(request, env);
  if (!user) return json({error:"Sign in to use Lightning Browser."},401);
  await ensureBrowserTable(env);
  const row = await env.DB.prepare("SELECT session_id,target_id FROM browser_sessions WHERE user_id=?").bind(user.id).first();
  if (!row) return json({error:"No browser session is open."},404);
  try {
    const info = await withBrowserSocket(env,row.session_id,row.target_id,socket => browserPageInfo(socket));
    if (browserCaptchaDetected(info)) return json({error:"The verification challenge is still visible. Complete it first, then try again."},409);
    await env.DB.prepare("UPDATE browser_sessions SET paused=0 WHERE user_id=?").bind(user.id).run();
    return json({ok:true,message:"Verification cleared. Browser automation resumed."});
  } catch (error) { return json({error:String(error?.message||error)},500); }
}
async function browserStopRoute(request, env) {
  const user = await userFor(request, env);
  if (!user) return json({error:"Sign in to use Lightning Browser."},401);
  await ensureBrowserTable(env);
  const row = await env.DB.prepare("SELECT session_id FROM browser_sessions WHERE user_id=?").bind(user.id).first();
  if (row?.session_id && env.BROWSER) { try { await env.BROWSER.closeSession(row.session_id); } catch {} }
  await env.DB.prepare("DELETE FROM browser_sessions WHERE user_id=?").bind(user.id).run();
  return json({ok:true});
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
  if(path==="/api/browser/start" && request.method==="POST") return browserStartRoute(request,env);
  if(path==="/api/browser/command" && request.method==="POST") return browserCommandRoute(request,env);
  if(path==="/api/browser/resume" && request.method==="POST") return browserResumeRoute(request,env);
  if(path==="/api/browser/stop" && request.method==="POST") return browserStopRoute(request,env);
  if(path==="/api/config" && request.method==="GET") return json({server:null});
  if(path==="/api/image-references" && request.method==="POST") return imageReferencesRoute(request,env);
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
      await ensureModerationTables(env);
      const blocked=await env.DB.prepare("SELECT username FROM blocked_users WHERE username_norm=?").bind(norm).first();
      if(blocked)return json({error:"This account name is blocked from Lightning."},403);
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
    await ensureModerationTables(env);
    const blocked=await env.DB.prepare("SELECT username FROM blocked_users WHERE username_norm=?").bind(norm).first();
    if(blocked)return json({error:"This account has been blocked from Lightning."},403);
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

  if(path==="/api/presence" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS user_presence (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,last_seen INTEGER NOT NULL,last_page TEXT NOT NULL DEFAULT 'Lightning')").run();
    let b={};try{b=await body(request)}catch{}
    const page=String(b.page||"Lightning").slice(0,40).replace(/[<>]/g,"");
    await env.DB.prepare("INSERT INTO user_presence(user_id,last_seen,last_page) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET last_seen=excluded.last_seen,last_page=excluded.last_page").bind(user.id,Math.floor(Date.now()/1000),page).run();
    return json({ok:true});
  }
  if(path==="/api/moderation/consent" && (request.method==="GET" || request.method==="POST")) {
    if(!user)return json({error:"Sign in required."},401);
    await ensureModerationTables(env);
    if(request.method==="GET") {
      const row=await env.DB.prepare("SELECT accepted_at FROM moderation_consents WHERE user_id=?").bind(user.id).first();
      return json({accepted:!!row,acceptedAt:row?.accepted_at||null});
    }
    let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    if(b.accept!==true)return json({error:"You must explicitly accept chat moderation storage."},400);
    await env.DB.prepare("INSERT INTO moderation_consents(user_id,accepted_at) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET accepted_at=excluded.accepted_at").bind(user.id,Math.floor(Date.now()/1000)).run();
    return json({ok:true,accepted:true});
  }
  if(path==="/api/moderation/chats" && (request.method==="POST" || request.method==="GET" || request.method==="DELETE")) {
    if(!user)return json({error:"Sign in required."},401);
    await ensureModerationTables(env);
    const consent=await env.DB.prepare("SELECT user_id FROM moderation_consents WHERE user_id=?").bind(user.id).first();
    if(!consent)return json({error:"Accept the chat moderation notice before syncing chats."},403);
    if(request.method==="DELETE") {
      const id=String(url.searchParams.get("id")||"");
      const result=id
        ? await env.DB.prepare("DELETE FROM chat_conversations WHERE user_id=? AND id=?").bind(user.id,id).run()
        : await env.DB.prepare("DELETE FROM chat_conversations WHERE user_id=?").bind(user.id).run();
      return json({ok:true,deleted:Number(result.meta?.changes||0)});
    }
    if(request.method==="GET") {
      const rows=await env.DB.prepare("SELECT id,title,messages_json,created_at,updated_at FROM chat_conversations WHERE user_id=? ORDER BY updated_at DESC").bind(user.id).all();
      return json({chats:(rows.results||[]).map(r=>({id:r.id,title:r.title,messages:JSON.parse(r.messages_json||"[]"),createdAt:r.created_at,updatedAt:r.updated_at}))});
    }
    let b;try{b=await body(request)}catch{return json({error:"Invalid or oversized chat data."},400)}
    const list=Array.isArray(b.chats)?b.chats:[];
    if(list.length>300)return json({error:"Too many conversations in one sync."},413);
    const now=Math.floor(Date.now()/1000);
    for(const c of list) {
      const id=String(c?.id||"").slice(0,100);
      if(!id)continue;
      const messages=Array.isArray(c.msgs)?c.msgs:[];
      const packed=JSON.stringify(messages);
      if(encoder.encode(packed).length>1500000)continue;
      const title=String(c.title||"New chat").slice(0,180);
      const terms=findProfanity(messages);
      await env.DB.prepare("INSERT INTO chat_conversations(id,user_id,title,messages_json,flagged_terms_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,id) DO UPDATE SET title=excluded.title,messages_json=excluded.messages_json,flagged_terms_json=excluded.flagged_terms_json,updated_at=excluded.updated_at").bind(id,user.id,title,packed,JSON.stringify(terms),Number(c.t)>0?Math.floor(Number(c.t)/1000):now,now).run();
    }
    return json({ok:true,saved:list.length});
  }
  if(path.startsWith("/api/admin/")) {
    const adminName=String(env.ADMIN_USERNAME||"").trim().toLowerCase();
    if(!adminName)return json({error:"Admin access is not configured. Set the ADMIN_USERNAME Worker secret."},503);
    if(!user)return json({error:"Sign in required."},401);
    if(user.username.toLowerCase()!==adminName)return json({error:"Administrator access denied."},403);
    await ensureAccountTables(env);
    await ensurePublishedTable(env);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS feature_usage (user_id TEXT PRIMARY KEY,trial_started_at INTEGER NOT NULL,text_used INTEGER NOT NULL DEFAULT 0,images_used INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL)").run();
    await ensureModerationTables(env);
    if(path==="/api/admin/moderation/flagged" && request.method==="GET") {
      const rows=await env.DB.prepare("SELECT c.id,c.title,c.flagged_terms_json,c.updated_at,u.id AS user_id,u.username FROM chat_conversations c JOIN users u ON u.id=c.user_id WHERE c.flagged_terms_json<>'[]' ORDER BY c.updated_at DESC LIMIT 250").all();
      return json({items:(rows.results||[]).map(r=>({id:r.id,title:r.title,terms:JSON.parse(r.flagged_terms_json||"[]"),updatedAt:r.updated_at,userId:r.user_id,username:r.username}))});
    }
    if(path==="/api/admin/moderation/chat" && request.method==="GET") {
      const id=String(url.searchParams.get("id")||"");
      const row=await env.DB.prepare("SELECT c.id,c.title,c.messages_json,c.flagged_terms_json,c.updated_at,u.id AS user_id,u.username FROM chat_conversations c JOIN users u ON u.id=c.user_id WHERE c.id=? ORDER BY c.updated_at DESC LIMIT 1").bind(id).first();
      if(!row)return json({error:"Conversation not found."},404);
      return json({chat:{id:row.id,title:row.title,username:row.username,userId:row.user_id,messages:JSON.parse(row.messages_json||"[]"),terms:JSON.parse(row.flagged_terms_json||"[]"),updatedAt:row.updated_at}});
    }
    if(path==="/api/admin/moderation/chat" && request.method==="DELETE") {
      const id=String(url.searchParams.get("id")||"");
      const result=await env.DB.prepare("DELETE FROM chat_conversations WHERE id=?").bind(id).run();
      return json({ok:true,deleted:Number(result.meta?.changes||0)});
    }
    if(path==="/api/admin/moderation/ban" && request.method==="POST") {
      let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
      const id=String(b.userId||"");
      if(!id||id===user.id)return json({error:"Invalid account."},400);
      const target=await env.DB.prepare("SELECT id,username,username_norm FROM users WHERE id=?").bind(id).first();
      if(!target)return json({error:"Account not found."},404);
      const reason=String(b.reason||"Profanity in chat").slice(0,300);
      const now=Math.floor(Date.now()/1000);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO blocked_users(username_norm,username,reason,blocked_at) VALUES(?,?,?,?) ON CONFLICT(username_norm) DO UPDATE SET username=excluded.username,reason=excluded.reason,blocked_at=excluded.blocked_at").bind(target.username_norm,target.username,reason,now),
        env.DB.prepare("DELETE FROM users WHERE id=?").bind(id)
      ]);
      return json({ok:true,username:target.username});
    }
    if(path==="/api/admin/moderation/blocked" && request.method==="GET") {
      const rows=await env.DB.prepare("SELECT username,reason,blocked_at FROM blocked_users ORDER BY blocked_at DESC LIMIT 200").all();
      return json({blocked:rows.results||[]});
    }
    if(path==="/api/admin/moderation/unblock" && request.method==="POST") {
      let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
      const norm=String(b.username||"").trim().toLowerCase();
      if(!norm)return json({error:"Missing username."},400);
      await env.DB.prepare("DELETE FROM blocked_users WHERE username_norm=?").bind(norm).run();
      return json({ok:true});
    }
    if(path==="/api/admin/overview" && request.method==="GET") {
      const [users,sessions,artifacts,workspaces]=await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS n FROM users").first(),
        env.DB.prepare("SELECT COUNT(*) AS n FROM sessions WHERE expires_at>?").bind(Math.floor(Date.now()/1000)).first(),
        env.DB.prepare("SELECT COUNT(*) AS n FROM published_artifacts").first(),
        env.DB.prepare("SELECT COUNT(*) AS n FROM user_data").first()
      ]);
      return json({admin:{username:user.username},stats:{users:Number(users?.n||0),sessions:Number(sessions?.n||0),artifacts:Number(artifacts?.n||0),workspaces:Number(workspaces?.n||0)}});
    }

    if(path==="/api/admin/friends-activity" && request.method==="GET") {
      await ensureSocialTables(env);
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS user_presence (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,last_seen INTEGER NOT NULL,last_page TEXT NOT NULL DEFAULT 'Lightning')").run();
      const rows=await env.DB.prepare("SELECT users.id,users.username,friendships.created_at AS friend_since,user_presence.last_seen,user_presence.last_page FROM friendships JOIN users ON users.id=CASE WHEN friendships.user_low=? THEN friendships.user_high ELSE friendships.user_low END LEFT JOIN user_presence ON user_presence.user_id=users.id WHERE friendships.user_low=? OR friendships.user_high=? ORDER BY COALESCE(user_presence.last_seen,0) DESC,users.username COLLATE NOCASE").bind(user.id,user.id,user.id).all();
      const now=Math.floor(Date.now()/1000);
      return json({friends:(rows.results||[]).map(r=>({id:r.id,username:r.username,lastSeen:r.last_seen||null,lastPage:r.last_page||"Unknown",online:!!r.last_seen&&now-r.last_seen<120,friendSince:r.friend_since}))});
    }
    if(path==="/api/admin/users" && request.method==="GET") {
      const q=String(url.searchParams.get("q")||"").trim().slice(0,40);
      const rows=await env.DB.prepare("SELECT users.id,users.username,users.created_at,COALESCE(feature_usage.text_used,0) AS text_used,COALESCE(feature_usage.images_used,0) AS images_used FROM users LEFT JOIN feature_usage ON feature_usage.user_id=users.id WHERE (?='' OR instr(lower(users.username),lower(?))>0) ORDER BY users.created_at DESC LIMIT 200").bind(q,q).all();
      return json({users:(rows.results||[]).map(r=>({id:r.id,username:r.username,createdAt:r.created_at,textUsed:Number(r.text_used||0),imagesUsed:Number(r.images_used||0)}))});
    }
    if(path==="/api/admin/users/reset" && request.method==="POST") {
      let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
      const id=String(b.id||"");if(!id)return json({error:"Missing account ID."},400);
      const now=Math.floor(Date.now()/1000),exists=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(id).first();
      if(!exists)return json({error:"Account not found."},404);
      await env.DB.prepare("INSERT INTO feature_usage(user_id,trial_started_at,text_used,images_used,updated_at) VALUES(?,?,0,0,?) ON CONFLICT(user_id) DO UPDATE SET trial_started_at=excluded.trial_started_at,text_used=0,images_used=0,updated_at=excluded.updated_at").bind(id,now,now).run();
      return json({ok:true});
    }
    if(path==="/api/admin/users" && request.method==="DELETE") {
      const id=String(url.searchParams.get("id")||"");if(!id)return json({error:"Missing account ID."},400);
      if(id===user.id)return json({error:"You cannot delete the administrator account while signed in."},400);
      const result=await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
      if(!result.meta?.changes)return json({error:"Account not found."},404);
      return json({ok:true});
    }
    return json({error:"Admin endpoint not found."},404);
  }

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
