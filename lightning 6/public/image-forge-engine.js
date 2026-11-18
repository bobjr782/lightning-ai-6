(function (global) {
  "use strict";

  function rgbToHsv(r, g, b) {
    r /= 255; g /= 255; b /= 255;
    var max = Math.max(r, g, b), min = Math.min(r, g, b), delta = max - min;
    var h = 0;
    if (delta) {
      if (max === r) h = 60 * (((g - b) / delta) % 6);
      else if (max === g) h = 60 * ((b - r) / delta + 2);
      else h = 60 * ((r - g) / delta + 4);
    }
    if (h < 0) h += 360;
    return [h, max ? delta / max : 0, max];
  }

  function circularHueDistance(a, b) {
    var d = Math.abs(a - b);
    return Math.min(d, 360 - d) / 180;
  }

  function segmentPixels(imageData, width, height, options) {
    options = options || {};
    var data = imageData && imageData.data ? imageData.data : imageData;
    if (!data || !Number.isInteger(width) || !Number.isInteger(height) || width < 8 || height < 8 || data.length !== width * height * 4) {
      throw new Error("Invalid image pixels");
    }
    var total = width * height;
    if (total > 262144) throw new Error("Analysis image is too large");

    var hue = new Float32Array(total), saturation = new Float32Array(total), value = new Float32Array(total);
    var luminance = new Float32Array(total), edge = new Uint8Array(total);
    for (var p = 0, q = 0; p < total; p++, q += 4) {
      var hsv = rgbToHsv(data[q], data[q + 1], data[q + 2]);
      hue[p] = hsv[0]; saturation[p] = hsv[1]; value[p] = hsv[2];
      luminance[p] = data[q] * 0.2126 + data[q + 1] * 0.7152 + data[q + 2] * 0.0722;
    }

    // Sobel edges stop colour similarity from washing across strong boundaries.
    for (var y = 1; y < height - 1; y++) {
      for (var x = 1; x < width - 1; x++) {
        var tl = luminance[(y - 1) * width + x - 1], tc = luminance[(y - 1) * width + x], tr = luminance[(y - 1) * width + x + 1];
        var ml = luminance[y * width + x - 1], mr = luminance[y * width + x + 1];
        var bl = luminance[(y + 1) * width + x - 1], bc = luminance[(y + 1) * width + x], br = luminance[(y + 1) * width + x + 1];
        var gx = -tl - 2 * ml - bl + tr + 2 * mr + br;
        var gy = -tl - 2 * tc - tr + bl + 2 * bc + br;
        edge[y * width + x] = Math.min(255, Math.round(Math.hypot(gx, gy) / 4));
      }
    }

    // HSV border groups handle coloured backgrounds and near-grey backgrounds.
    var bins = new Map();
    function addBorderPixel(p) {
      var q = p * 4;
      if (data[q + 3] < 24) return;
      var hBin = saturation[p] < 0.12 ? 24 : Math.floor(hue[p] / 15);
      var sBin = Math.min(3, Math.floor(saturation[p] * 4));
      var vBin = Math.min(3, Math.floor(value[p] * 4));
      var key = hBin + ":" + sBin + ":" + vBin;
      var bin = bins.get(key);
      if (!bin) { bin = { count: 0, sin: 0, cos: 0, saturation: 0, value: 0 }; bins.set(key, bin); }
      var radians = hue[p] * Math.PI / 180;
      bin.count++;
      bin.sin += Math.sin(radians);
      bin.cos += Math.cos(radians);
      bin.saturation += saturation[p];
      bin.value += value[p];
    }
    for (var bx = 0; bx < width; bx++) { addBorderPixel(bx); addBorderPixel((height - 1) * width + bx); }
    for (var by = 1; by < height - 1; by++) { addBorderPixel(by * width); addBorderPixel(by * width + width - 1); }
    if (!bins.size) throw new Error("No usable border colours");

    var palette = Array.from(bins.values()).sort(function (a, b) { return b.count - a.count; }).slice(0, 12).map(function (bin) {
      var h = Math.atan2(bin.sin, bin.cos) * 180 / Math.PI;
      if (h < 0) h += 360;
      return { h: h, s: bin.saturation / bin.count, v: bin.value / bin.count, count: bin.count };
    });

    var threshold = Number.isFinite(options.colorThreshold) ? options.colorThreshold : 0.17;
    var edgeThreshold = Number.isFinite(options.edgeThreshold) ? options.edgeThreshold : 42;
    var distanceCache = new Float32Array(total);
    function backgroundDistance(p) {
      var q = p * 4;
      if (data[q + 3] < 24) return 0;
      var best = Infinity;
      for (var k = 0; k < palette.length; k++) {
        var c = palette[k];
        var hWeight = Math.min(saturation[p], c.s);
        var dh = circularHueDistance(hue[p], c.h) * hWeight * 1.25;
        var ds = (saturation[p] - c.s) * 0.85;
        var dv = (value[p] - c.v) * 0.8;
        var d = dh * dh + ds * ds + dv * dv;
        if (d < best) best = d;
      }
      return best;
    }
    function isBackground(p) {
      var d = distanceCache[p];
      if (d < 0) { d = backgroundDistance(p); distanceCache[p] = d; }
      // Strong edges block weak matches; very close colour matches still pass.
      return d <= threshold && (edge[p] < edgeThreshold || d <= threshold * 0.22);
    }
    distanceCache.fill(-1);

    var background = new Uint8Array(total), queue = new Int32Array(total);
    var head = 0, tail = 0, matchingEdges = 0;
    function seed(p) { if (!background[p] && isBackground(p)) { background[p] = 1; queue[tail++] = p; matchingEdges++; } }
    for (var sx = 0; sx < width; sx++) { seed(sx); seed((height - 1) * width + sx); }
    for (var sy = 1; sy < height - 1; sy++) { seed(sy * width); seed(sy * width + width - 1); }
    var borderCount = width * 2 + Math.max(0, height - 2) * 2;
    if (matchingEdges < borderCount * 0.08) throw new Error("Could not identify a consistent background around the image edge");
    while (head < tail) {
      var current = queue[head++], cx = current % width, cy = (current / width) | 0;
      for (var dy = -1; dy <= 1; dy++) for (var dx = -1; dx <= 1; dx++) {
        if (!dx && !dy) continue;
        var nx = cx + dx, ny = cy + dy;
        if (nx < 0 || ny < 0 || nx >= width || ny >= height) continue;
        var next = ny * width + nx;
        if (!background[next] && isBackground(next)) { background[next] = 1; queue[tail++] = next; }
      }
    }

    // Connected-component labels keep the main subject and meaningful islands.
    var seen = new Uint8Array(total), labels = new Int32Array(total), stack = new Int32Array(total), components = [];
    for (var start = 0; start < total; start++) {
      if (background[start] || seen[start] || data[start * 4 + 3] < 24) continue;
      var componentId = components.length + 1, count = 0, minX = width, minY = height, maxX = -1, maxY = -1;
      var sp = 0; stack[sp++] = start; seen[start] = 1;
      while (sp) {
        var z = stack[--sp], zx = z % width, zy = (z / width) | 0;
        labels[z] = componentId; count++;
        if (zx < minX) minX = zx; if (zx > maxX) maxX = zx;
        if (zy < minY) minY = zy; if (zy > maxY) maxY = zy;
        for (var ddy = -1; ddy <= 1; ddy++) for (var ddx = -1; ddx <= 1; ddx++) {
          if (!ddx && !ddy) continue;
          var nnx = zx + ddx, nny = zy + ddy;
          if (nnx < 0 || nny < 0 || nnx >= width || nny >= height) continue;
          var ni = nny * width + nnx;
          if (!background[ni] && !seen[ni] && data[ni * 4 + 3] >= 24) { seen[ni] = 1; stack[sp++] = ni; }
        }
      }
      components.push({ id: componentId, count: count, minX: minX, minY: minY, maxX: maxX, maxY: maxY });
    }
    components.sort(function (a, b) { return b.count - a.count; });
    if (!components.length) throw new Error("No foreground object was detected");
    var largest = components[0].count;
    if (largest < total * 0.025) throw new Error("Detected object is too small");
    var keepIds = new Set();
    components.forEach(function (part, index) { if (index === 0 || part.count >= Math.max(8, largest * 0.003)) keepIds.add(part.id); });

    var keep = new Uint8Array(total), foreground = 0, minKeepX = width, minKeepY = height, maxKeepX = -1, maxKeepY = -1, edgeForeground = 0;
    var hueSin = 0, hueCos = 0, satSum = 0, edgeCount = 0, keptComponents = 0;
    for (var ci = 0; ci < components.length; ci++) if (keepIds.has(components[ci].id)) keptComponents++;
    for (var py = 0; py < height; py++) for (var px = 0; px < width; px++) {
      var index = py * width + px;
      if (!keepIds.has(labels[index])) continue;
      keep[index] = 1; foreground++;
      if (px < minKeepX) minKeepX = px; if (px > maxKeepX) maxKeepX = px;
      if (py < minKeepY) minKeepY = py; if (py > maxKeepY) maxKeepY = py;
      if (px === 0 || py === 0 || px === width - 1 || py === height - 1) edgeForeground++;
      if (saturation[index] > 0.08) { var hr = hue[index] * Math.PI / 180; hueSin += Math.sin(hr); hueCos += Math.cos(hr); }
      satSum += saturation[index];
      if (edge[index] >= edgeThreshold) edgeCount++;
    }
    if (foreground < total * 0.025) throw new Error("Foreground mask was too weak");
    if (edgeForeground) throw new Error("The detected object touches the image edge");
    var boxWidth = maxKeepX - minKeepX + 1, boxHeight = maxKeepY - minKeepY + 1;
    if (boxWidth < width * 0.07 || boxHeight < height * 0.07) throw new Error("Detected object is too small");
    var dominantHue = hueSin === 0 && hueCos === 0 ? null : (Math.atan2(hueSin, hueCos) * 180 / Math.PI + 360) % 360;
    return {
      mask: keep,
      background: background,
      width: width,
      height: height,
      bounds: { left: minKeepX, top: minKeepY, right: maxKeepX + 1, bottom: maxKeepY + 1 },
      stats: {
        foregroundPercent: foreground / total * 100,
        dominantHue: dominantHue === null ? null : Math.round(dominantHue),
        averageSaturation: satSum / foreground,
        edgeDensity: edgeCount / foreground * 100,
        componentCount: keptComponents,
        aspectRatio: boxWidth / boxHeight,
        paletteGroups: palette.length
      }
    };
  }

  function analyzeImageElement(img, options) {
    options = options || {};
    var w = img && (img.naturalWidth || img.width), h = img && (img.naturalHeight || img.height);
    if (!w || !h || w * h > 12000000) throw new Error("Image is too large or has no dimensions");
    var sampleSize = Math.max(96, Math.min(384, Number(options.sampleSize) || 256));
    var scale = Math.min(1, sampleSize / Math.max(w, h));
    var sw = Math.max(1, Math.round(w * scale)), sh = Math.max(1, Math.round(h * scale));
    var sample = document.createElement("canvas"); sample.width = sw; sample.height = sh;
    var sampleContext = sample.getContext("2d", { willReadFrequently: true });
    if (!sampleContext) throw new Error("Canvas processing is unavailable");
    sampleContext.drawImage(img, 0, 0, sw, sh);
    var pixels = sampleContext.getImageData(0, 0, sw, sh);
    var result = segmentPixels(pixels, sw, sh, options);
    var pad = Math.max(2, Math.round(Math.max(result.bounds.right - result.bounds.left, result.bounds.bottom - result.bounds.top) * 0.018));
    var cropLeft = Math.max(0, result.bounds.left - pad), cropTop = Math.max(0, result.bounds.top - pad);
    var cropRight = Math.min(sw, result.bounds.right + pad), cropBottom = Math.min(sh, result.bounds.bottom + pad);
    var left = Math.floor(cropLeft / sw * w), top = Math.floor(cropTop / sh * h);
    var right = Math.min(w, Math.ceil(cropRight / sw * w)), bottom = Math.min(h, Math.ceil(cropBottom / sh * h));
    var cropWidth = right - left, cropHeight = bottom - top;
    var outputScale = Math.min(1, 1024 / Math.max(cropWidth, cropHeight));
    var output = document.createElement("canvas");
    output.width = Math.max(1, Math.round(cropWidth * outputScale));
    output.height = Math.max(1, Math.round(cropHeight * outputScale));
    if (!output.width || !output.height) throw new Error("Invalid crop bounds");
    var context = output.getContext("2d", { willReadFrequently: true });
    context.drawImage(img, left, top, cropWidth, cropHeight, 0, 0, output.width, output.height);
    var outPixels = context.getImageData(0, 0, output.width, output.height), out = outPixels.data;
    for (var oy = 0; oy < output.height; oy++) for (var ox = 0; ox < output.width; ox++) {
      var sourceX = left + (ox + 0.5) / output.width * cropWidth;
      var sourceY = top + (oy + 0.5) / output.height * cropHeight;
      var sx = Math.min(sw - 1, Math.max(0, Math.floor(sourceX / w * sw)));
      var sy = Math.min(sh - 1, Math.max(0, Math.floor(sourceY / h * sh)));
      var p = sy * sw + sx, at = (oy * output.width + ox) * 4;
      if (!result.mask[p]) { out[at + 3] = 0; continue; }
      var nearBackground = false;
      for (var dy = -1; dy <= 1 && !nearBackground; dy++) for (var dx = -1; dx <= 1; dx++) {
        var nx = sx + dx, ny = sy + dy;
        if (nx >= 0 && ny >= 0 && nx < sw && ny < sh && result.background[ny * sw + nx]) { nearBackground = true; break; }
      }
      if (nearBackground) out[at + 3] = Math.min(out[at + 3], 220);
    }
    context.putImageData(outPixels, 0, 0);
    return { canvas: output, stats: result.stats, bounds: result.bounds, sampleSize: sw + "×" + sh, outputSize: output.width + "×" + output.height };
  }

  global.ImageForgeEngine = Object.freeze({
    version: "0.2.0-hsv-sobel",
    rgbToHsv: rgbToHsv,
    segmentPixels: segmentPixels,
    analyzeImageElement: analyzeImageElement
  });
})(window);
