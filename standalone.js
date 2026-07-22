/**
 * Standalone exported-book reader.
 *
 * Runs with no server: the whole text payload (chapters, sentences, speakers,
 * avatars) is inlined into index.html as window.BOOK_PAYLOAD, because fetch()
 * is blocked on file:// origins. Audio stays as sibling .mp3 files and is
 * loaded by setting <audio src>, which file:// does allow.
 *
 * When the book was exported with a password the payload is AES-GCM
 * ciphertext (base64) and audio files are encrypted too; those need fetch(),
 * so a password-protected export must be served over http(s), not opened
 * straight off disk. index.html says so in that case.
 */
(() => {
    'use strict';

    const $ = (id) => document.getElementById(id);
    const enc = window.BOOK_ENCRYPTED === true;

    let book = null;      // decoded payload
    let key = null;       // CryptoKey when encrypted
    let chapterIdx = 0;
    let sentences = [];   // current chapter, [{index, text, speaker?}]
    let stamps = [];      // current chapter timings [{index, start, end}]
    let curSentence = -1;
    let objectUrl = null;

    const audio = new Audio();
    audio.preload = 'metadata';

    // ---------- crypto ----------
    const b64ToBuf = (b64) => {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    };

    async function deriveKey(password) {
        const material = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: b64ToBuf(window.BOOK_SALT),
                iterations: window.BOOK_ITERATIONS || 210000,
                hash: 'SHA-256'
            },
            material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    }

    // iv (12 bytes) || ciphertext
    async function decryptBuf(buf, k) {
        const bytes = new Uint8Array(buf);
        return crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: bytes.slice(0, 12) }, k, bytes.slice(12));
    }

    // ---------- boot ----------
    async function start(password) {
        if (enc) {
            key = await deriveKey(password);
            // Throws if the password is wrong — AES-GCM auth tag won't verify
            const plain = await decryptBuf(b64ToBuf(window.BOOK_PAYLOAD).buffer, key);
            book = JSON.parse(new TextDecoder().decode(plain));
        } else {
            book = window.BOOK_PAYLOAD;
        }

        $('gate').classList.add('hidden');
        $('app').classList.remove('hidden');
        document.title = book.title || 'Book';
        $('bookTitleHdr').textContent = book.title || 'Book';
        const au = $('bookAuthorHdr');
        if (book.author) { au.textContent = book.author; au.classList.remove('hidden'); }
        else au.classList.add('hidden');

        renderToc();

        // URL parameters let a link deep-link into the book:
        //   ?s=<index>   jump to a specific sentence (data-sentence index)
        //   ?speed=<n>   set playback speed (0.5–3)
        //   ?play=1      begin playing on load (with ?s, from that sentence)
        // Also accepted in the hash (#s=42&speed=1.5) for file:// friendliness.
        const params = new URLSearchParams(location.search ||
            (location.hash.startsWith('#') ? location.hash.slice(1) : ''));
        const urlIndex = parseInt(params.get('s') ?? params.get('index'), 10);
        const urlSpeed = parseFloat(params.get('speed'));
        const urlPlay = params.get('play') === '1';

        // Pick the starting chapter: the one containing ?s, else the saved spot
        let startCh = Number(localStorage.getItem(posKey('ch')) || 0);
        if (!(Number.isFinite(startCh) && book.chapters[startCh])) startCh = 0;
        if (Number.isFinite(urlIndex)) {
            const ci = book.chapters.findIndex(c =>
                c.html && c.html.includes(`data-sentence="${urlIndex}"`));
            if (ci >= 0) startCh = ci;
        }

        // Capture the saved playhead before openChapter runs — opening a chapter
        // rewrites the bookmark time to ~0, so read it first to restore it after.
        const savedTime = Number(localStorage.getItem(posKey('t')) || 0);

        await openChapter(startCh);
        wire();

        if (Number.isFinite(urlSpeed)) setSpeed(urlSpeed);   // URL overrides saved
        if (Number.isFinite(urlIndex)) gotoSentence(urlIndex, urlPlay);
        else resumeTo(savedTime);   // auto-resume where we left off, paused
    }

    const posKey = (k) => `stbook:${book?.id || 'book'}:${k}`;

    // ---------- resume position (single per-book bookmark: chapter + time) ----------
    let lastPosSave = 0;
    function savePos() {
        if (book) localStorage.setItem(posKey('t'), String(audio.currentTime || 0));
    }
    // Seek to a saved time once the audio can accept it — same metadata guard as
    // gotoSentence (setting currentTime too early is silently dropped). Leaves
    // playback paused: the reader presses play to continue from the saved spot.
    function resumeTo(time) {
        if (!(time > 0)) return;
        const doSeek = () => { audio.currentTime = time; syncHighlight(); updateProgress(); };
        if (audio.readyState >= 1 && audio.duration) doSeek();
        else audio.addEventListener('loadedmetadata', doSeek, { once: true });
    }

    // ---------- table of contents ----------
    function renderToc() {
        const el = $('tocList');
        el.innerHTML = '';
        book.chapters.forEach((c, i) => {
            const a = document.createElement('a');
            a.href = '#';
            a.textContent = c.title || `Section ${i + 1}`;
            a.onclick = (e) => {
                e.preventDefault();
                openChapter(i);
                // On a phone the TOC is an overlay — close it after picking
                if (window.matchMedia('(max-width: 760px)').matches) $('toc').classList.remove('open');
            };
            el.appendChild(a);
        });
    }

    function markToc() {
        [...$('tocList').children].forEach((a, i) =>
            a.classList.toggle('current', i === chapterIdx));
    }

    // ---------- chapters ----------
    async function openChapter(i) {
        const ch = book.chapters[i];
        if (!ch) return;
        chapterIdx = i;
        localStorage.setItem(posKey('ch'), String(i));

        $('page').innerHTML = ch.html || '<p><em>This section is empty.</em></p>';
        $('bookTitle').textContent = ch.title || `Section ${i + 1}`;
        sentences = ch.sentences || [];
        curSentence = -1;
        markToc();
        $('reader').scrollTop = 0;

        // Click a sentence to start reading from it
        $('page').querySelectorAll('.sentence').forEach(el => {
            el.onclick = () => {
                const idx = Number(el.dataset.sentence);
                const s = stamps.find(t => t.index === idx);
                if (s) { audio.currentTime = s.start; if (audio.paused) audio.play(); }
            };
        });
        applyUnderline(); // re-wrap quotes for the new section if the toggle is on

        await loadAudio(ch);
        updateBar();
        updateProgress();
        // Realign the bookmark time with the freshly-opened chapter (currentTime
        // is 0 after load), so a (chapter, time) pair is never mismatched.
        savePos();
    }

    async function loadAudio(ch) {
        stamps = [];
        stopAudio();
        if (!ch.audio) { updateBar(); return; }

        stamps = ch.timestamps || [];
        try {
            if (enc) {
                // Encrypted audio must be fetched and decrypted — http(s) only
                const buf = await (await fetch(ch.audio)).arrayBuffer();
                const plain = await decryptBuf(buf, key);
                objectUrl = URL.createObjectURL(new Blob([plain], { type: 'audio/mpeg' }));
                audio.src = objectUrl;
            } else {
                // Direct src: works from file:// where fetch() would not
                audio.src = ch.audio;
            }
            audio.load();
        } catch (err) {
            console.warn('Audio unavailable:', err.message);
            stamps = [];
        }
        updateBar();
    }

    function stopAudio() {
        audio.pause();
        audio.removeAttribute('src');
        if (objectUrl) { URL.revokeObjectURL(objectUrl); objectUrl = null; }
    }

    // ---------- playback / highlight ----------
    // Track the playhead on requestAnimationFrame rather than the audio
    // 'timeupdate' event: timeupdate fires only ~4x/second, which lags the
    // highlight noticeably (up to a whole short sentence). rAF samples
    // audio.currentTime every frame, so the highlight lands on the sentence
    // actually being spoken.
    // Move the highlight to the sentence whose time window contains the
    // playhead. Called from the rAF loop (during playback) and from explicit
    // user actions (seek bar, prev/next). It is deliberately NOT wired to the
    // audio 'seeked'/'loadedmetadata' events: a deep-link seek that the browser
    // can't satisfy yet fires 'seeked' with currentTime still 0, which would
    // otherwise yank the highlight back to sentence 0.
    function syncHighlight() {
        if (!stamps.length) return;
        const t = audio.currentTime;
        let i = curSentence >= 0 ? stamps.findIndex(s => s.index === curSentence) : 0;
        if (i < 0) i = 0;
        while (i < stamps.length - 1 && t >= stamps[i + 1].start) i++;
        while (i > 0 && t < stamps[i].start) i--;
        highlight(stamps[i].index);
    }

    let rafId = null;
    function tick() {
        rafId = null;
        syncHighlight();
        updateProgress();
        const now = Date.now();
        if (now - lastPosSave > 2000) { lastPosSave = now; savePos(); }
        if (!audio.paused && !audio.ended) rafId = requestAnimationFrame(tick);
    }
    function startTicking() { if (rafId == null) rafId = requestAnimationFrame(tick); }

    audio.addEventListener('play', () => { updateBar(); startTicking(); });
    audio.addEventListener('pause', () => { updateBar(); updateProgress(); savePos(); });
    // Load-time / seek events update only the progress bar, never the highlight
    audio.addEventListener('seeked', updateProgress);
    audio.addEventListener('loadedmetadata', updateProgress);
    audio.addEventListener('durationchange', updateProgress);

    audio.addEventListener('ended', () => {
        if (chapterIdx < book.chapters.length - 1) {
            openChapter(chapterIdx + 1).then(() => audio.play().catch(() => {}));
        } else {
            updateBar();
            updateProgress();
        }
    });

    function fmtTime(s) {
        if (!isFinite(s) || s < 0) s = 0;
        const m = Math.floor(s / 60);
        const sec = Math.floor(s % 60);
        return `${m}:${sec < 10 ? '0' : ''}${sec}`;
    }

    function updateProgress() {
        const dur = audio.duration || 0;
        const cur = audio.currentTime || 0;
        const pct = dur ? (cur / dur) * 100 : 0;
        $('seekFill').style.width = pct + '%';
        $('seekHead').style.left = pct + '%';
        $('curTime').textContent = fmtTime(cur);
        $('durTime').textContent = fmtTime(dur);
    }

    function highlight(idx) {
        if (idx === curSentence) return;
        curSentence = idx;
        const page = $('page');
        page.querySelectorAll('.sentence.on').forEach(e => e.classList.remove('on'));
        const el = page.querySelector(`.sentence[data-sentence="${idx}"]`);
        if (el) {
            el.classList.add('on');
            const r = el.getBoundingClientRect();
            const rr = $('reader').getBoundingClientRect();
            if (r.top < rr.top + 60 || r.bottom > rr.bottom - 60) {
                el.scrollIntoView({ block: 'center', behavior: 'smooth' });
            }
        }
        showSpeaker(sentences.find(s => s.index === idx));
    }

    function showSpeaker(s) {
        const box = $('speaker');
        const who = s && s.speaker;
        if (!who || who === 'Narrator') { box.classList.add('hidden'); return; }
        $('speakerName').textContent = who;
        const src = (book.avatars || {})[who];
        const img = $('speakerImg');
        if (src) { img.src = src; img.style.display = ''; } else { img.style.display = 'none'; }
        box.classList.remove('hidden');
    }

    function jumpSentence(delta) {
        if (!stamps.length) return;
        let i = stamps.findIndex(s => s.index === curSentence);
        if (i < 0) i = 0;
        i = Math.max(0, Math.min(stamps.length - 1, i + delta));
        audio.currentTime = stamps[i].start;
        highlight(stamps[i].index); // move the highlight now, don't wait for a tick
        updateProgress();
    }

    // Jump to a specific sentence index (from a deep link). Highlights and
    // scrolls to it; if the section has audio, seeks there too.
    function gotoSentence(idx, play) {
        const el = $('page').querySelector(`.sentence[data-sentence="${idx}"]`);
        if (el) {
            highlight(idx);
            el.scrollIntoView({ block: 'center' });
        }
        const s = stamps.find(t => t.index === idx);
        if (!s) return;
        // Seek only once the audio can accept it. Setting currentTime before
        // metadata loads is silently dropped (it stays 0), and the resulting
        // tick would then drag the highlight back to sentence 0.
        const doSeek = () => { audio.currentTime = s.start; if (play) audio.play().catch(() => {}); };
        if (audio.readyState >= 1 && audio.duration) doSeek();
        else audio.addEventListener('loadedmetadata', doSeek, { once: true });
    }

    function updateBar() {
        const has = !!audio.src && stamps.length > 0;
        $('play').disabled = !has;
        $('prev').disabled = !has;
        $('next').disabled = !has;
        $('play').textContent = audio.paused ? '▶' : '⏸';
        $('prevCh').disabled = chapterIdx <= 0;
        $('nextCh').disabled = chapterIdx >= book.chapters.length - 1;
        $('status').textContent = has
            ? `${stamps.length} sentences${book.chapters[chapterIdx].multivoice ? ' · multivoice' : ''}`
            : (book.chapters[chapterIdx].audio ? 'audio unavailable' : 'no audio for this section');
    }

    // ---------- preferences (persist across sessions) ----------
    const PREF = {
        get(k, d) { const v = localStorage.getItem('stpref:' + k); return v == null ? d : v; },
        set(k, v) { localStorage.setItem('stpref:' + k, v); }
    };

    function setSpeed(v) {
        v = Math.min(3, Math.max(0.5, Number(v) || 1));
        audio.playbackRate = v;
        $('speed').value = v;
        $('speedVal').textContent = v.toFixed(2).replace(/0$/, '') + '×';
        PREF.set('speed', v);
    }
    function setVolume(v) {
        v = Math.min(100, Math.max(0, Number(v)));
        audio.volume = v / 100;
        $('vol').value = v;
        $('volIc').textContent = v === 0 ? '🔇' : v < 50 ? '🔉' : '🔊';
        PREF.set('vol', v);
    }
    function setWide(on) {
        $('page').classList.toggle('wide', on);
        $('widthToggle').classList.toggle('active', on);
        PREF.set('wide', on ? '1' : '0');
    }
    function setUnderline(on) {
        underlineOn = on;
        $('ulQuotes').classList.toggle('active', on);
        applyUnderline();
        PREF.set('ul', on ? '1' : '0');
    }

    // Wrap quoted runs in the current page in <span class="q-ul">. Quote state
    // is tracked across text nodes so a quote spanning several sentence spans
    // is fully underlined. Toggling off unwraps them.
    let underlineOn = false;
    function applyUnderline() {
        const page = $('page');
        // Always clear first
        page.querySelectorAll('span.q-ul').forEach(s => {
            s.replaceWith(document.createTextNode(s.textContent));
        });
        page.normalize();
        if (!underlineOn) return;

        const OPEN = '“"«', CLOSE = '”"»';
        let open = false;
        const walker = document.createTreeWalker(page, NodeFilter.SHOW_TEXT);
        const edits = [];
        let node;
        while ((node = walker.nextNode())) {
            const text = node.nodeValue;
            if (!/[“"«”»]/.test(text) && !open) continue;
            const parts = []; // {text, quoted}
            let buf = '';
            for (const ch of text) {
                if (!open && OPEN.includes(ch)) {
                    if (buf) { parts.push({ text: buf, quoted: false }); buf = ''; }
                    open = true; buf += ch;
                } else if (open && CLOSE.includes(ch)) {
                    buf += ch; parts.push({ text: buf, quoted: true }); buf = ''; open = false;
                } else buf += ch;
            }
            if (buf) parts.push({ text: buf, quoted: open });
            if (parts.length > 1 || (parts[0] && parts[0].quoted)) edits.push({ node, parts });
        }
        for (const { node, parts } of edits) {
            const frag = document.createDocumentFragment();
            for (const p of parts) {
                if (p.quoted) {
                    const span = document.createElement('span');
                    span.className = 'q-ul';
                    span.textContent = p.text;
                    frag.appendChild(span);
                } else {
                    frag.appendChild(document.createTextNode(p.text));
                }
            }
            node.parentNode.replaceChild(frag, node);
        }
    }

    // ---------- wiring ----------
    function wire() {
        $('play').onclick = () => audio.paused ? audio.play() : audio.pause();
        $('prev').onclick = () => jumpSentence(-1);
        $('next').onclick = () => jumpSentence(1);
        $('prevCh').onclick = () => openChapter(chapterIdx - 1);
        $('nextCh').onclick = () => openChapter(chapterIdx + 1);
        // ☰ hides/shows the contents. On a wide screen the sidebar collapses
        // in place; on a narrow screen it slides in as an overlay.
        $('tocBtn').onclick = () => {
            const toc = $('toc');
            // On a phone the sidebar is an overlay (transient 'open' state, not
            // persisted). On a wide screen it collapses in place, and that choice
            // is remembered across sessions.
            if (window.matchMedia('(max-width: 760px)').matches) toc.classList.toggle('open');
            else PREF.set('toc', toc.classList.toggle('collapsed') ? '1' : '0');
        };

        $('speed').oninput = () => setSpeed($('speed').value);
        $('vol').oninput = () => setVolume($('vol').value);
        $('ulQuotes').onclick = () => setUnderline(!underlineOn);
        $('widthToggle').onclick = () => setWide(!$('page').classList.contains('wide'));

        // Collapsible options row (chevron in the transport bar)
        const optBar = $('optionsBar'), optToggle = $('optionsToggle');
        const setOptions = (open) => {
            optBar.classList.toggle('collapsed', !open);
            optToggle.classList.toggle('collapsed', !open);
            PREF.set('opts', open ? '1' : '0');
        };
        optToggle.onclick = () => setOptions(optBar.classList.contains('collapsed'));
        setOptions(PREF.get('opts', '1') === '1');

        // Seek bar: click or drag to scrub
        const seek = $('seek');
        const seekTo = (clientX) => {
            const r = seek.getBoundingClientRect();
            const frac = Math.min(1, Math.max(0, (clientX - r.left) / r.width));
            if (audio.duration) { audio.currentTime = frac * audio.duration; syncHighlight(); updateProgress(); }
        };
        let dragging = false;
        seek.addEventListener('pointerdown', (e) => { dragging = true; seek.setPointerCapture(e.pointerId); seekTo(e.clientX); });
        seek.addEventListener('pointermove', (e) => { if (dragging) seekTo(e.clientX); });
        seek.addEventListener('pointerup', () => { dragging = false; });

        // Restore saved preferences
        setSpeed(PREF.get('speed', 1));
        setVolume(PREF.get('vol', 100));
        setWide(PREF.get('wide', '0') === '1');
        setUnderline(PREF.get('ul', '0') === '1');
        // Restore the desktop TOC collapsed state ('.collapsed' only hides the
        // sidebar at wide widths; on a phone the sidebar is display:none until
        // opened, so this is a harmless no-op there).
        $('toc').classList.toggle('collapsed', PREF.get('toc', '0') === '1');

        document.addEventListener('keydown', (e) => {
            const t = e.target.tagName;
            if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT') return;
            if (e.key === ' ') { e.preventDefault(); $('play').click(); }
            else if (e.key === 'ArrowRight') { e.preventDefault(); jumpSentence(e.shiftKey ? 1 : 5); }
            else if (e.key === 'ArrowLeft') { e.preventDefault(); jumpSentence(e.shiftKey ? -1 : -5); }
            else if (e.key === '+' || e.key === '=') { e.preventDefault(); setSpeed(audio.playbackRate + 0.25); }
            else if (e.key === '-') { e.preventDefault(); setSpeed(audio.playbackRate - 0.25); }
        });
    }

    // ---------- entry ----------
    window.addEventListener('DOMContentLoaded', () => {
        if (!enc) {
            start().catch(err => {
                document.body.innerHTML =
                    `<pre style="padding:2rem">Could not open this book: ${err.message}</pre>`;
            });
            return;
        }
        $('gate').classList.remove('hidden');
        const go = async () => {
            const pw = $('pw').value;
            if (!pw) return;
            $('gateErr').textContent = '';
            $('unlock').disabled = true;
            try {
                await start(pw);
            } catch {
                $('gateErr').textContent = 'Wrong password.';
                $('unlock').disabled = false;
                $('pw').select();
            }
        };
        $('unlock').onclick = go;
        $('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
        $('pw').focus();
    });
})();
