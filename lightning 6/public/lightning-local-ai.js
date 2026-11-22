/* Lightning Local AI
   Runs an open-weight language model inside the browser using WebGPU.
   Model weights are downloaded once and cached by WebLLM in browser storage.
   No prompts, account data, or API keys are sent to an AI server.
*/
(() => {
  "use strict";
  const MODEL_DEFAULT = "Qwen3-0.6B-q4f16_1-MLC";
  let engine = null;
  let loadedModel = "";
  let loading = null;
  let webllmModule = null;

  const say = (callback, message) => {
    try { if (typeof callback === "function") callback(message); } catch (_) {}
  };

  async function load(model, onProgress) {
    model = model || MODEL_DEFAULT;
    if (engine && loadedModel === model) return engine;
    if (loading && loading.model === model) return loading.promise;
    if (!navigator.gpu) {
      throw new Error("This browser does not expose WebGPU. Try the latest Chrome or Edge, and check that hardware acceleration is enabled.");
    }

    const promise = (async () => {
      say(onProgress, "Preparing local AI engine…");
      const adapter = await navigator.gpu.requestAdapter();
      if (!adapter) throw new Error("No compatible GPU was found. WebGPU may be disabled by this computer's administrator or graphics driver.");
      if (!webllmModule) {
        say(onProgress, "Loading the local AI runtime…");
        webllmModule = await import("https://esm.run/@mlc-ai/web-llm");
      }
      try {
        if (navigator.storage && navigator.storage.persist) await navigator.storage.persist();
      } catch (_) {}

      engine = null;
      loadedModel = "";
      const started = Date.now();
      const created = await webllmModule.CreateMLCEngine(model, {
        initProgressCallback: report => {
          const text = report && report.text ? report.text : "Downloading and preparing model…";
          const pct = report && Number.isFinite(report.progress) ? " " + Math.round(report.progress * 100) + "%" : "";
          const elapsed = Math.max(1, Math.round((Date.now() - started) / 1000));
          say(onProgress, text + pct + " · " + elapsed + "s");
        }
      });
      engine = created;
      loadedModel = model;
      say(onProgress, "Local model ready · " + model);
      return engine;
    })();

    loading = { model, promise };
    try {
      return await promise;
    } finally {
      if (loading && loading.promise === promise) loading = null;
    }
  }

  async function generate(messages, options) {
    options = options || {};
    const model = options.model || MODEL_DEFAULT;
    const active = await load(model, options.onProgress);
    const safeMessages = (Array.isArray(messages) ? messages : [])
      .filter(m => m && ["system", "user", "assistant"].includes(m.role))
      .map(m => {
        if (typeof m.content !== "string") {
          throw new Error("The local model currently accepts text messages only. Remove image attachments or switch to an online vision model.");
        }
        return { role: m.role, content: m.content };
      });

    say(options.onProgress, "Thinking locally · your text stays on this computer…");
    const stream = await active.chat.completions.create({
      messages: safeMessages,
      temperature: 0.7,
      max_tokens: 1800,
      stream: true
    });

    let full = "";
    for await (const chunk of stream) {
      const token = chunk && chunk.choices && chunk.choices[0] && chunk.choices[0].delta
        ? (chunk.choices[0].delta.content || "") : "";
      if (token) {
        full += token;
        try { if (typeof options.onToken === "function") options.onToken(full, token); } catch (_) {}
      }
    }
    return full;
  }

  window.LightningLocalAI = {
    generate,
    load,
    isReady: () => !!engine && !!loadedModel,
    currentModel: () => loadedModel,
    defaultModel: MODEL_DEFAULT,
    models: {
      "Qwen3-0.6B-q4f16_1-MLC": { label: "Qwen3 0.6B", memory: "about 1.4 GB GPU memory" },
      "Qwen3-1.7B-q4f16_1-MLC": { label: "Qwen3 1.7B", memory: "about 2.0 GB GPU memory" },
      "Qwen3-4B-q4f16_1-MLC": { label: "Qwen3 4B", memory: "about 3.4 GB GPU memory" }
    }
  };
})();
