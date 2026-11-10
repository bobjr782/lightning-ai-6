const SESSION_DAYS = 30;
const MAX_DATA_BYTES = 20000000;
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
}
function friendPair(a,b){return a<b?[a,b]:[b,a];}

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
function imageRateLimit(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const row = IMAGE_RATE.get(ip);
  if (!row || now - row.start > 60000) {
    IMAGE_RATE.set(ip, { start: now, count: 1 });
    if (IMAGE_RATE.size > 2000) {
      for (const [key, value] of IMAGE_RATE) if (now - value.start > 60000) IMAGE_RATE.delete(key);
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
  const limit = imageRateLimit(request);
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
        promptUsed: prompt,
        model: "FLUX.2 Dev · 25 steps",
        width,
        height,
        seed
      });
    } catch (qualityError) {
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
          promptUsed: prompt,
          model: "FLUX.2 Klein 9B (backup)",
          width,
          height,
          seed
        });
      } catch (backupError) {
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
          promptUsed: prompt,
          model: "FLUX.2 Klein 4B (last-resort backup)",
          width,
          height,
          seed
        });
      }
    }

  } catch (error) {
    const detail = String(error?.message || error || "");
    const status = /quota|limit|neuron|billing|paid plan/i.test(detail) ? 429 : 502;
    return json({
      error: status === 429
        ? "The free image-generation allowance may be used up. Try again after the daily reset."
        : "The image model is temporarily unavailable. Please try again in a moment."
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
  if(path==="/api/config" && request.method==="GET") return json({server:null});
  if(path==="/api/image" && request.method==="POST") return imageRoute(request, env);
  if(path==="/api/chat" && request.method==="POST") return chatRoute(request,env);
  if(path==="/api/generate" && request.method==="POST") return generateRoute(request, env);
  if(!env.DB) return json({error:"Account database is not configured yet."},503);
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
  if(path==="/api/me" && request.method==="GET") {
    if(!user)return json({user:null},401);
    const usage=await ensureUsage(user,env);
    return json({user,entitlement:entitlement(usage)});
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
  if(path==="/api/friends" && request.method==="GET") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    const [friends,requests]=await Promise.all([
      env.DB.prepare("SELECT users.username,users.id FROM friendships JOIN users ON users.id=CASE WHEN friendships.user_low=? THEN friendships.user_high ELSE friendships.user_low END WHERE friendships.user_low=? OR friendships.user_high=? ORDER BY users.username").bind(user.id,user.id,user.id).all(),
      env.DB.prepare("SELECT friend_requests.id,users.username AS from FROM friend_requests JOIN users ON users.id=friend_requests.sender_id WHERE friend_requests.recipient_id=? AND friend_requests.status='pending' ORDER BY friend_requests.created_at DESC").bind(user.id).all()
    ]);
    return json({friends:friends.results||[],requests:requests.results||[]});
  }
  if(path==="/api/friends/request" && request.method==="POST") {
    if(!user)return json({error:"Sign in required."},401);
    await ensureSocialTables(env);
    let b;try{b=await body(request)}catch{return json({error:"Invalid request."},400)}
    const username=String(b.username||"").trim().toLowerCase();
    if(!username)return json({error:"Enter a username."},400);
    const target=await env.DB.prepare("SELECT id,username FROM users WHERE username_norm=?").bind(username).first();
    if(!target)return json({error:"No Lightning account found with that username."},404);
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
    const target=String(b.username||"").trim().toLowerCase(), artifact=JSON.stringify(b.artifact??{});
    if(!target)return json({error:"Enter the username to share with."},400);
    if(encoder.encode(artifact).length>70000)return json({error:"That creation is too large to share. Images are automatically compressed before sharing."},413);
    const recipient=await env.DB.prepare("SELECT id FROM users WHERE username_norm=?").bind(target).first();
    if(!recipient)return json({error:"No Lightning account found with that username."},404);
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
  return env.ASSETS.fetch(request);
}
export default {
  async fetch(request, env, ctx) {
    try { return await route(request,env); }
    catch(e) { return json({error:"Server error. Please try again.",detail:env.ENVIRONMENT==="development"?String(e):undefined},500); }
  }
};
