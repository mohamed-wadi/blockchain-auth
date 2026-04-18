/**
 * attack_map.js — Real-time attack map canvas renderer
 * Used by attack-map.html
 */

const AttackMap = (() => {

    let canvas, ctx, _animId;
    const attackPoints = [];

    /** latLon → pixel coords */
    function latLonToXY(lat, lon, w, h) {
        return {
            x: ((lon + 180) / 360) * w,
            y: ((90 - lat) / 180) * h,
        };
    }

    /** Init canvas and start render loop */
    function init(canvasEl) {
        canvas = canvasEl;
        ctx = canvas.getContext('2d');
        resize();
        window.addEventListener('resize', resize);
        _animId = requestAnimationFrame(loop);
    }

    function resize() {
        canvas.width = canvas.clientWidth || window.innerWidth;
        canvas.height = canvas.clientHeight || 420;
    }

    /** Add an attack event to the map */
    function addAttack({ lat, lon, success, country, city }) {
        if (!lat && !lon) return;
        attackPoints.push({ lat, lon, success, country, city, time: Date.now() });
        if (attackPoints.length > 150) attackPoints.shift();
    }

    const SERVER = { lat: 33.57, lon: -7.59 }; // Casablanca

    function loop() {
        const w = canvas.width, h = canvas.height;
        ctx.clearRect(0, 0, w, h);

        // Grid
        ctx.strokeStyle = 'rgba(10,25,50,0.9)';
        ctx.lineWidth = 0.5;
        for (let x = 0; x < w; x += 60) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
        for (let y = 0; y < h; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

        const srv = latLonToXY(SERVER.lat, SERVER.lon, w, h);

        // Server dot
        ctx.beginPath();
        ctx.arc(srv.x, srv.y, 10, 0, Math.PI * 2);
        const grad = ctx.createRadialGradient(srv.x, srv.y, 2, srv.x, srv.y, 10);
        grad.addColorStop(0, 'rgba(0,255,157,0.8)');
        grad.addColorStop(1, 'rgba(0,255,157,0)');
        ctx.fillStyle = grad;
        ctx.fill();
        ctx.strokeStyle = '#00ff9d';
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.fillStyle = '#00ff9d';
        ctx.font = '11px monospace';
        ctx.fillText('🛡 Serveur', srv.x + 14, srv.y + 4);

        const now = Date.now();
        attackPoints.forEach(pt => {
            const age = (now - pt.time) / 1000;
            const alpha = Math.max(0, 1 - age / 9);
            if (alpha <= 0) return;

            const pos = latLonToXY(pt.lat, pt.lon, w, h);
            const ok = pt.success;

            // Attack line
            ctx.beginPath();
            ctx.moveTo(pos.x, pos.y);
            ctx.lineTo(srv.x, srv.y);
            ctx.strokeStyle = ok
                ? `rgba(0,255,136,${alpha * 0.3})`
                : `rgba(255,60,90,${alpha * 0.55})`;
            ctx.lineWidth = 1;
            ctx.stroke();

            // Source dot
            const r = 5 + Math.sin(now / 400 + pt.lat) * 2;
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);
            ctx.fillStyle = ok
                ? `rgba(0,255,136,${alpha})`
                : `rgba(255,60,90,${alpha})`;
            ctx.fill();

            if (alpha > 0.5 && pt.country) {
                ctx.fillStyle = `rgba(180,210,255,${alpha * 0.9})`;
                ctx.font = '10px monospace';
                ctx.fillText(pt.country, pos.x + 8, pos.y - 4);
            }
        });

        _animId = requestAnimationFrame(loop);
    }

    function destroy() { cancelAnimationFrame(_animId); }

    return { init, addAttack, resize, destroy };
})();
