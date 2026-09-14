/**
 * ScamShield - Scanner Logic & Client-Side Image/QR Processing
 */

window.ScannerApp = {
  activeScreenshotFile: null,
  isOcrRunning: false,
  activeOcrPromise: null,

  async handleScreenshotFile(file) {
    if (!file) return;
    this.activeScreenshotFile = file;

    // 1. Preview the image
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = document.getElementById('screenshot-preview-img');
      if (img) img.src = e.target.result;
      const box = document.getElementById('screenshot-preview-box');
      if (box) box.style.display = 'block';
    };
    reader.readAsDataURL(file);

    // 2. Start client-side neural OCR
    await this.runOcrOnScreenshot(file);
  },

  updateOcrProgress(statusText, percent) {
    const container = document.getElementById('ocr-progress-container');
    const statusEl = document.getElementById('ocr-status-text');
    const pctEl = document.getElementById('ocr-percentage');
    const barEl = document.getElementById('ocr-progress-bar');

    if (container) container.style.display = 'block';
    if (statusEl) {
      const label = statusEl.querySelector('span:last-child') || statusEl;
      label.innerText = statusText;
    }
    if (pctEl) pctEl.innerText = `${percent}%`;
    if (barEl) barEl.style.width = `${percent}%`;
  },

  hideOcrProgress() {
    const container = document.getElementById('ocr-progress-container');
    if (container) {
      setTimeout(() => {
        container.style.display = 'none';
      }, 800);
    }
  },

  async prepareImageForOcr(fileOrBlob) {
    return new Promise((resolve) => {
      const img = new Image();
      const url = URL.createObjectURL(fileOrBlob);
      img.onload = () => {
        URL.revokeObjectURL(url);
        const maxDim = 1600;
        let w = img.width;
        let h = img.height;
        if (w > maxDim || h > maxDim) {
          const ratio = Math.min(maxDim / w, maxDim / h);
          w = Math.floor(w * ratio);
          h = Math.floor(h * ratio);
          const canvas = document.createElement('canvas');
          canvas.width = w;
          canvas.height = h;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, w, h);
          resolve(canvas);
        } else {
          resolve(img);
        }
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        resolve(fileOrBlob);
      };
      img.src = url;
    });
  },

  async runOcrOnScreenshot(file) {
    const badge = document.getElementById('ocr-badge-status');
    const textArea = document.getElementById('screenshot-text-override');
    if (badge) badge.style.display = 'none';

    if (!window.Tesseract) {
      console.warn('Tesseract.js not available on window.');
      return;
    }

    this.isOcrRunning = true;
    this.updateOcrProgress('Initializing neural OCR engine...', 10);

    this.activeOcrPromise = (async () => {
      try {
        const imageSource = await this.prepareImageForOcr(file);

        const result = await Tesseract.recognize(
          imageSource,
          'eng',
          {
            logger: m => {
              if (m.status === 'recognizing text') {
                const pct = Math.round((m.progress || 0) * 100);
                this.updateOcrProgress(`Recognizing text characters... ${pct}%`, pct);
              } else if (m.status === 'loading tesseract core') {
                this.updateOcrProgress('Loading WebAssembly engine...', 25);
              } else if (m.status === 'initializing tesseract') {
                this.updateOcrProgress('Initializing OCR neural models...', 45);
              } else if (m.status === 'loading language traineddata') {
                this.updateOcrProgress('Loading English dictionary model...', 65);
              }
            }
          }
        );

        const text = result?.data?.text ? result.data.text.trim() : '';
        if (text) {
          if (textArea) {
            textArea.value = text;
          }
          if (badge) {
            const wordCount = text.split(/\s+/).filter(Boolean).length;
            badge.innerText = `✅ OCR Extracted (${wordCount} words)`;
            badge.style.display = 'inline-block';
          }
          this.updateOcrProgress('✅ Text extracted successfully!', 100);
        } else {
          this.updateOcrProgress('No clear text detected in screenshot. You can paste or type below.', 100);
        }
      } catch (err) {
        console.warn('Tesseract OCR error:', err);
        this.updateOcrProgress('⚠️ OCR notice: unable to extract text. You can paste or type below.', 100);
      } finally {
        this.isOcrRunning = false;
        this.hideOcrProgress();
      }
    })();

    await this.activeOcrPromise;
  },

  qrCameraStream: null,
  qrCameraAnimationId: null,
  qrCameraFacing: 'environment',
  qrVideoDevices: [],
  qrCurrentDeviceIndex: 0,
  barcodeDetector: null,
  barcodeDetectorChecked: false,
  isScanningFrame: false,
  isQrDetected: false,
  lastScanTimestamp: 0,
  scanIntervalMs: 140,

  async initBarcodeDetector() {
    if (this.barcodeDetectorChecked) return;
    this.barcodeDetectorChecked = true;
    if ('BarcodeDetector' in window) {
      try {
        const formats = await BarcodeDetector.getSupportedFormats();
        if (formats && (formats.includes('qr_code') || formats.includes('all'))) {
          this.barcodeDetector = new BarcodeDetector({ formats: ['qr_code'] });
          console.log('BarcodeDetector hardware engine initialized for QR decoding.');
        } else {
          this.barcodeDetector = null;
        }
      } catch (e) {
        console.warn('BarcodeDetector initialization notice:', e);
        this.barcodeDetector = null;
      }
    }
  },

  showCameraError(message) {
    const errorBanner = document.getElementById('qr-camera-error-banner');
    if (errorBanner) {
      errorBanner.innerHTML = `<strong>⚠️ Camera Notice:</strong> ${message}`;
      errorBanner.style.display = 'block';
    } else {
      alert(message);
    }
  },

  clearCameraError() {
    const errorBanner = document.getElementById('qr-camera-error-banner');
    if (errorBanner) errorBanner.style.display = 'none';
  },

  activateUploadMode() {
    this.stopQrCamera();
    this.clearCameraError();
    const btnCamera = document.getElementById('btn-qr-mode-camera');
    const btnUpload = document.getElementById('btn-qr-mode-upload');
    if (btnCamera) btnCamera.classList.remove('active-mode');
    if (btnUpload) btnUpload.classList.add('active-mode');
    const fileInput = document.getElementById('qr-file-input');
    if (fileInput) fileInput.click();
  },

  async enumerateCameras() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
      this.qrVideoDevices = [];
      return;
    }
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const videoDevices = devices.filter(d => d.kind === 'videoinput');

      // Prioritize standard color webcams over Windows Hello IR sensors
      videoDevices.sort((a, b) => {
        const aIsIR = /ir|infrared|hello/i.test(a.label);
        const bIsIR = /ir|infrared|hello/i.test(b.label);
        if (aIsIR && !bIsIR) return 1;
        if (!aIsIR && bIsIR) return -1;
        return 0;
      });

      this.qrVideoDevices = videoDevices;
      this.updateCameraSwitchButton();
    } catch (e) {
      console.warn('enumerateDevices warning:', e);
    }
  },

  updateCameraSwitchButton() {
    const btnFlip = document.getElementById('btn-flip-camera');
    const labelSpan = document.getElementById('flip-camera-label') || (btnFlip ? btnFlip.querySelector('span') : null);
    if (!btnFlip || !labelSpan) return;

    if (this.qrVideoDevices.length > 1) {
      labelSpan.innerText = `🔄 Switch Cam (${this.qrCurrentDeviceIndex + 1}/${this.qrVideoDevices.length})`;
      const activeLabel = this.qrVideoDevices[this.qrCurrentDeviceIndex]?.label || 'Active Camera';
      btnFlip.title = `Current: ${activeLabel}. Click to switch camera.`;
      btnFlip.style.display = 'inline-flex';
    } else {
      labelSpan.innerText = '🔄 Flip Lens';
      btnFlip.title = 'Switch front/rear lens';
      btnFlip.style.display = 'inline-flex';
    }
  },

  async cycleCameraDevice() {
    if (this.qrVideoDevices.length > 1) {
      this.qrCurrentDeviceIndex = (this.qrCurrentDeviceIndex + 1) % this.qrVideoDevices.length;
      const nextDevice = this.qrVideoDevices[this.qrCurrentDeviceIndex];
      await this.openQrCamera(nextDevice.deviceId);
    } else {
      this.qrCameraFacing = this.qrCameraFacing === 'environment' ? 'user' : 'environment';
      await this.openQrCamera();
    }
  },

  toggleCameraFacing() {
    return this.cycleCameraDevice();
  },

  async openQrCamera(preferredDeviceId = null) {
    this.clearCameraError();
    await this.initBarcodeDetector();

    const btnCamera = document.getElementById('btn-qr-mode-camera');
    const btnUpload = document.getElementById('btn-qr-mode-upload');
    if (btnCamera) btnCamera.classList.add('active-mode');
    if (btnUpload) btnUpload.classList.remove('active-mode');

    const container = document.getElementById('qr-camera-container');
    const dropzone = document.getElementById('qr-dropzone');
    const previewBox = document.getElementById('qr-preview-box');
    const statusText = document.getElementById('camera-status-text');
    const video = document.getElementById('qr-camera-video');

    if (!window.isSecureContext && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
      this.showCameraError(
        'Camera access requires a Secure Context (HTTPS or localhost). ' +
        'If accessing from another device across your network, use an HTTPS tunnel or use "Upload Image File" below.'
      );
      this.stopQrCamera();
      return;
    }

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      this.showCameraError(
        'Webcam access is not supported by your browser or environment. Please use "Upload Image File".'
      );
      this.stopQrCamera();
      return;
    }

    // Stop previous stream & cancel animation loops
    if (this.qrCameraStream) {
      try {
        this.qrCameraStream.getTracks().forEach(t => t.stop());
      } catch (e) {}
      this.qrCameraStream = null;
    }
    if (this.qrCameraAnimationId) {
      cancelAnimationFrame(this.qrCameraAnimationId);
      this.qrCameraAnimationId = null;
    }

    this.isQrDetected = false;
    this.isScanningFrame = false;
    this.lastScanTimestamp = 0;

    if (dropzone) dropzone.style.display = 'none';
    if (previewBox) previewBox.style.display = 'none';
    if (container) container.style.display = 'block';
    if (statusText) {
      statusText.innerText = 'Requesting camera stream...';
      if (statusText.parentElement) statusText.parentElement.classList.remove('detected');
    }

    let stream = null;
    let targetDeviceId = preferredDeviceId;

    if (!targetDeviceId && this.qrVideoDevices.length > 0 && this.qrVideoDevices[this.qrCurrentDeviceIndex]) {
      targetDeviceId = this.qrVideoDevices[this.qrCurrentDeviceIndex].deviceId;
    }

    // Level 1: Try with ideal constraints (specific deviceId or facingMode, 1280x720)
    try {
      const constraints = {
        video: targetDeviceId
          ? { deviceId: { exact: targetDeviceId }, width: { ideal: 1280 }, height: { ideal: 720 } }
          : { facingMode: { ideal: this.qrCameraFacing }, width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false
      };
      stream = await navigator.mediaDevices.getUserMedia(constraints);
    } catch (err1) {
      console.warn('Preferred camera constraints rejected, attempting device-only fallback:', err1);
      try {
        // Level 2: Try deviceId or facingMode without resolution requirements
        const fallbackConstraints = targetDeviceId
          ? { video: { deviceId: { exact: targetDeviceId } }, audio: false }
          : { video: { facingMode: this.qrCameraFacing }, audio: false };
        stream = await navigator.mediaDevices.getUserMedia(fallbackConstraints);
      } catch (err2) {
        console.warn('Device-specific fallback failed, attempting basic unconstrained video:', err2);
        try {
          // Level 3: Basic unconstrained video (works on any compliant webcam or virtual source)
          stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
        } catch (err3) {
          console.error('All camera attempts failed:', err3);
          let msg = 'Unable to access camera device.';
          if (err3.name === 'NotAllowedError' || err3.name === 'PermissionDeniedError') {
            msg = 'Camera permission was denied. Please click the camera/lock icon in your browser URL bar, grant permission, and try again.';
          } else if (err3.name === 'NotFoundError' || err3.name === 'DevicesNotFoundError') {
            msg = 'No camera device found on this system. Please connect a webcam or use "Upload Image File".';
          } else if (err3.name === 'NotReadableError' || err3.name === 'TrackStartError') {
            msg = 'Camera is currently in use by another application (Zoom, Teams, Discord, etc.). Please release it and retry.';
          } else if (err3.name === 'OverconstrainedError') {
            msg = 'The requested camera configuration is not supported by your hardware.';
          } else {
            msg = `Camera error: ${err3.message || err3.name}`;
          }
          this.showCameraError(msg);
          this.stopQrCamera();
          return;
        }
      }
    }

    this.qrCameraStream = stream;

    // Discover devices now that permission is granted (labels will be available)
    await this.enumerateCameras();

    // Match current device index to active track
    const activeTrack = stream.getVideoTracks()[0];
    if (activeTrack) {
      const activeSettings = activeTrack.getSettings ? activeTrack.getSettings() : {};
      if (activeSettings.deviceId && this.qrVideoDevices.length > 0) {
        const foundIdx = this.qrVideoDevices.findIndex(d => d.deviceId === activeSettings.deviceId);
        if (foundIdx !== -1) {
          this.qrCurrentDeviceIndex = foundIdx;
        }
      }
      this.updateCameraSwitchButton();

      // Mirror user-facing / front cameras for natural interaction
      const label = (activeTrack.label || '').toLowerCase();
      const isFrontFacing = activeSettings.facingMode === 'user' ||
        this.qrCameraFacing === 'user' ||
        (/front|user|facetime|integrated/i.test(label) && !/back|rear|environment/i.test(label));

      if (video) {
        if (isFrontFacing) {
          video.classList.add('is-mirrored');
        } else {
          video.classList.remove('is-mirrored');
        }
      }
    }

    if (video) {
      video.muted = true;
      video.defaultMuted = true;
      video.playsInline = true;
      video.autoplay = true;
      video.setAttribute('playsinline', 'true');
      video.setAttribute('muted', 'true');
      video.srcObject = stream;

      try {
        await video.play();
      } catch (playErr) {
        console.warn('video.play() notice:', playErr);
      }
    }

    if (statusText) {
      const devLabel = activeTrack?.label ? ` · ${activeTrack.label.substring(0, 22)}` : '';
      statusText.innerText = `Align QR code within reticle${devLabel}...`;
    }

    const overlay = document.querySelector('.camera-hud-overlay');
    if (overlay) overlay.classList.remove('qr-success-flash');

    // Kick off adaptive throttled scan loop
    this.qrCameraAnimationId = requestAnimationFrame(ts => this.scanCameraTick(ts));
  },

  stopQrCamera() {
    if (this.qrCameraAnimationId) {
      cancelAnimationFrame(this.qrCameraAnimationId);
      this.qrCameraAnimationId = null;
    }

    if (this.qrCameraStream) {
      try {
        this.qrCameraStream.getTracks().forEach(track => {
          track.stop();
        });
      } catch (e) {
        console.warn('Track stop error:', e);
      }
      this.qrCameraStream = null;
    }

    this.isQrDetected = false;
    this.isScanningFrame = false;

    const video = document.getElementById('qr-camera-video');
    if (video) {
      video.srcObject = null;
      video.classList.remove('is-mirrored');
    }

    const container = document.getElementById('qr-camera-container');
    const dropzone = document.getElementById('qr-dropzone');
    if (container) container.style.display = 'none';
    if (dropzone) dropzone.style.display = 'block';

    const btnCamera = document.getElementById('btn-qr-mode-camera');
    const btnUpload = document.getElementById('btn-qr-mode-upload');
    if (btnCamera) btnCamera.classList.remove('active-mode');
    if (btnUpload) btnUpload.classList.remove('active-mode');

    const overlay = document.querySelector('.camera-hud-overlay');
    if (overlay) overlay.classList.remove('qr-success-flash');
  },

  onQrDetected(payload) {
    if (!payload || !payload.trim() || this.isQrDetected) return;
    this.isQrDetected = true;

    // Immediately stop requestAnimationFrame loop
    if (this.qrCameraAnimationId) {
      cancelAnimationFrame(this.qrCameraAnimationId);
      this.qrCameraAnimationId = null;
    }

    const cleanPayload = payload.trim();
    const payloadInput = document.getElementById('qr-payload-input');
    if (payloadInput) {
      payloadInput.value = cleanPayload;
    }

    const statusText = document.getElementById('camera-status-text');
    if (statusText) {
      const displaySnippet = cleanPayload.length > 36 ? cleanPayload.substring(0, 36) + '...' : cleanPayload;
      statusText.innerText = `🎯 QR Decoded: ${displaySnippet}`;
      if (statusText.parentElement) statusText.parentElement.classList.add('detected');
    }

    const overlay = document.querySelector('.camera-hud-overlay');
    if (overlay) overlay.classList.add('qr-success-flash');

    if (navigator.vibrate) {
      try { navigator.vibrate(120); } catch (e) {}
    }

    // Auto-close camera after brief 550ms confirmation flash
    setTimeout(() => {
      this.stopQrCamera();
      const btn = document.getElementById('btn-qr-scan');
      if (btn) btn.focus();
    }, 550);
  },

  async captureCurrentCameraFrame() {
    const video = document.getElementById('qr-camera-video');
    const canvas = document.getElementById('qr-camera-canvas');
    const statusText = document.getElementById('camera-status-text');

    if (!video || !this.qrCameraStream || video.videoWidth === 0) {
      this.showCameraError('Camera stream is not ready for capture yet.');
      return;
    }

    if (statusText) statusText.innerText = 'Analyzing captured frame...';

    const vw = video.videoWidth;
    const vh = video.videoHeight;
    canvas.width = vw;
    canvas.height = vh;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(video, 0, 0, vw, vh);

    // 1. Native BarcodeDetector on full frame canvas
    if (this.barcodeDetector) {
      try {
        const barcodes = await this.barcodeDetector.detect(canvas);
        if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
          this.onQrDetected(barcodes[0].rawValue);
          return;
        }
      } catch (e) {
        console.warn('Snapshot detector notice:', e);
      }
    }

    // 2. jsQR on full resolution
    if (window.jsQR) {
      try {
        const imageData = ctx.getImageData(0, 0, vw, vh);
        const code = jsQR(imageData.data, vw, vh, {
          inversionAttempts: 'attemptBoth'
        });
        if (code && code.data && code.data.trim()) {
          this.onQrDetected(code.data);
          return;
        }
      } catch (err) {
        console.warn('Snapshot jsQR notice:', err);
      }
    }

    if (statusText) {
      statusText.innerText = 'No QR found in snapshot. Move closer or adjust lighting.';
      setTimeout(() => {
        if (!this.isQrDetected && this.qrCameraStream && statusText) {
          statusText.innerText = 'Align QR code within cyber reticle...';
        }
      }, 2500);
    }
  },

  async scanCameraTick(timestamp) {
    if (!this.qrCameraStream || this.isQrDetected) return;

    // Rate-limiting throttle & concurrency guard: ~7 FPS scanning prevents thread pegging
    if (timestamp - this.lastScanTimestamp < this.scanIntervalMs || this.isScanningFrame) {
      this.qrCameraAnimationId = requestAnimationFrame(ts => this.scanCameraTick(ts));
      return;
    }

    const video = document.getElementById('qr-camera-video');
    const canvas = document.getElementById('qr-camera-canvas');

    if (!video || video.readyState < 2 || video.videoWidth === 0 || video.videoHeight === 0) {
      this.qrCameraAnimationId = requestAnimationFrame(ts => this.scanCameraTick(ts));
      return;
    }

    this.isScanningFrame = true;
    this.lastScanTimestamp = timestamp;

    try {
      // 1. Native BarcodeDetector (hardware accelerated)
      if (this.barcodeDetector) {
        try {
          const barcodes = await this.barcodeDetector.detect(video);
          if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
            this.onQrDetected(barcodes[0].rawValue);
            this.isScanningFrame = false;
            return;
          }
        } catch (detectorErr) {
          // Fall through to jsQR
        }
      }

      // 2. High-Resolution Center Reticle Native Crop via jsQR
      if (canvas && window.jsQR) {
        const vw = video.videoWidth;
        const vh = video.videoHeight;

        // Extract central 62% square (where the reticle is aimed) at full 1:1 sensor resolution
        const cropSize = Math.floor(Math.min(vw, vh) * 0.62);
        const cropX = Math.floor((vw - cropSize) / 2);
        const cropY = Math.floor((vh - cropSize) / 2);

        if (canvas.width !== cropSize || canvas.height !== cropSize) {
          canvas.width = cropSize;
          canvas.height = cropSize;
        }

        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(video, cropX, cropY, cropSize, cropSize, 0, 0, cropSize, cropSize);
        const centerData = ctx.getImageData(0, 0, cropSize, cropSize);
        const centerCode = jsQR(centerData.data, cropSize, cropSize, {
          inversionAttempts: 'attemptBoth'
        });

        if (centerCode && centerCode.data && centerCode.data.trim().length > 0) {
          this.onQrDetected(centerCode.data);
          this.isScanningFrame = false;
          return;
        }

        // 3. Fallback: Scaled Full Frame (in case QR code is off-center)
        const maxDim = 640;
        let scale = 1;
        if (vw > maxDim || vh > maxDim) {
          scale = Math.min(maxDim / vw, maxDim / vh);
        }
        const w = Math.floor(vw * scale);
        const h = Math.floor(vh * scale);

        if (canvas.width !== w || canvas.height !== h) {
          canvas.width = w;
          canvas.height = h;
        }

        ctx.drawImage(video, 0, 0, w, h);
        const fullData = ctx.getImageData(0, 0, w, h);
        const fullCode = jsQR(fullData.data, w, h, {
          inversionAttempts: 'attemptBoth'
        });

        if (fullCode && fullCode.data && fullCode.data.trim().length > 0) {
          this.onQrDetected(fullCode.data);
          this.isScanningFrame = false;
          return;
        }
      }
    } catch (tickErr) {
      console.warn('scanCameraTick warning:', tickErr);
    } finally {
      this.isScanningFrame = false;
    }

    if (this.qrCameraStream && !this.isQrDetected) {
      this.qrCameraAnimationId = requestAnimationFrame(ts => this.scanCameraTick(ts));
    }
  },

  handleQrFile(file) {
    if (!file) return;
    this.stopQrCamera();
    const btnUpload = document.getElementById('btn-qr-mode-upload');
    if (btnUpload) btnUpload.classList.add('active-mode');

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = document.getElementById('qr-preview-img');
      img.src = e.target.result;
      document.getElementById('qr-preview-box').style.display = 'block';

      // Client-side QR decoding using BarcodeDetector + jsQR with attemptBoth
      const imageObj = new Image();
      imageObj.onload = async () => {
        // 1. Try BarcodeDetector first
        if (this.barcodeDetector) {
          try {
            const barcodes = await this.barcodeDetector.detect(imageObj);
            if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
              document.getElementById('qr-payload-input').value = barcodes[0].rawValue.trim();
              return;
            }
          } catch (e) {}
        }

        // 2. jsQR fallback with inversionAttempts: 'attemptBoth'
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          canvas.width = imageObj.width;
          canvas.height = imageObj.height;
          ctx.drawImage(imageObj, 0, 0);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          if (window.jsQR) {
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
              inversionAttempts: 'attemptBoth'
            });
            if (code && code.data && code.data.trim()) {
              document.getElementById('qr-payload-input').value = code.data.trim();
            }
          }
        } catch (err) {
          console.warn('Local QR file decode error:', err);
        }
      };
      imageObj.src = e.target.result;
    };
    reader.readAsDataURL(file);
  },

  async submitUrl(event) {
    event.preventDefault();
    const url = document.getElementById('input-url').value.trim();
    if (!url) return;
    App.showLoading('btn-url-scan');
    try {
      const res = await fetch('/api/v1/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, privacy_mode: App.isPrivacyMode() })
      });
      const data = await res.json();
      App.renderResult(data);
    } catch (err) {
      alert('Error analyzing URL: ' + err.message);
    } finally {
      App.hideLoading('btn-url-scan', '🛡️ Run Security Analysis');
    }
  },

  async submitMessage(event) {
    event.preventDefault();
    const message = document.getElementById('input-message').value.trim();
    if (!message) return;
    App.showLoading('btn-message-scan');
    try {
      const res = await fetch('/api/v1/analyze/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, privacy_mode: App.isPrivacyMode() })
      });
      const data = await res.json();
      App.renderResult(data);
    } catch (err) {
      alert('Error analyzing message: ' + err.message);
    } finally {
      App.hideLoading('btn-message-scan', '🛡️ Analyze Message Signals');
    }
  },

  async submitEmail(event) {
    event.preventDefault();
    const sender = document.getElementById('input-email-sender').value.trim();
    const reply_to = document.getElementById('input-email-reply').value.trim();
    const subject = document.getElementById('input-email-subject').value.trim();
    const body = document.getElementById('input-email-body').value.trim();

    App.showLoading('btn-email-scan');
    try {
      const res = await fetch('/api/v1/analyze/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, reply_to, subject, body, privacy_mode: App.isPrivacyMode() })
      });
      const data = await res.json();
      App.renderResult(data);
    } catch (err) {
      alert('Error analyzing email: ' + err.message);
    } finally {
      App.hideLoading('btn-email-scan', '🛡️ Inspect Email Authenticity');
    }
  },

  async submitScreenshot(event) {
    event.preventDefault();

    // If OCR is still executing, await its completion
    if (this.isOcrRunning && this.activeOcrPromise) {
      App.showLoading('btn-screenshot-scan');
      const btn = document.getElementById('btn-screenshot-scan');
      if (btn) btn.innerHTML = `<span>⏳ Extracting Text with AI OCR...</span>`;
      try {
        await this.activeOcrPromise;
      } catch (e) {}
    }

    const textOverride = (document.getElementById('screenshot-text-override')?.value || '').trim();

    if (this.activeScreenshotFile) {
      App.showLoading('btn-screenshot-scan');
      const formData = new FormData();
      formData.append('file', this.activeScreenshotFile);
      formData.append('extracted_text', textOverride);
      formData.append('privacy_mode', App.isPrivacyMode());

      try {
        const res = await fetch('/api/v1/analyze/upload-image', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        App.renderResult(data);
      } catch (err) {
        alert('Error analyzing screenshot file: ' + err.message);
      } finally {
        App.hideLoading('btn-screenshot-scan', '🛡️ Evaluate Visual Fraud Indicators');
      }
    } else if (textOverride) {
      App.showLoading('btn-screenshot-scan');
      try {
        const res = await fetch('/api/v1/analyze/image', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            extracted_text: textOverride,
            image_name: 'Manual Text Inspection',
            privacy_mode: App.isPrivacyMode()
          })
        });
        const data = await res.json();
        App.renderResult(data);
      } catch (err) {
        alert('Error analyzing text: ' + err.message);
      } finally {
        App.hideLoading('btn-screenshot-scan', '🛡️ Evaluate Visual Fraud Indicators');
      }
    } else {
      alert('Please upload a screenshot image or paste text to analyze.');
    }
  },

  async submitQr(event) {
    event.preventDefault();
    const payload = document.getElementById('qr-payload-input').value.trim();
    if (!payload) return;
    App.showLoading('btn-qr-scan');
    try {
      const res = await fetch('/api/v1/analyze/qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, privacy_mode: App.isPrivacyMode() })
      });
      const data = await res.json();
      App.renderResult(data);
    } catch (err) {
      alert('Error analyzing QR code: ' + err.message);
    } finally {
      App.hideLoading('btn-qr-scan', '🛡️ Verify QR Destination');
    }
  }
};
