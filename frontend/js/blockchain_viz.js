/**
 * blockchain_viz.js — 3D blockchain visualizer helper
 * Used by blockchain-explorer.html (Three.js powered)
 */

const BlockchainViz = (() => {

    /** Create a single block mesh with wireframe overlay */
    function createBlockMesh(THREE, index, totalBlocks) {
        const geo = new THREE.BoxGeometry(1.8, 1.2, 1.2);
        const color = index === 0 ? 0x00ff88 : index === totalBlocks - 1 ? 0xffaa00 : 0x0055ff;
        const emissive = index === 0 ? 0x004422 : 0x000033;

        const mat = new THREE.MeshPhongMaterial({
            color, emissive, wireframe: false,
            transparent: true, opacity: 0.88,
        });
        const cube = new THREE.Mesh(geo, mat);

        // Wireframe edge overlay
        const edges = new THREE.EdgesGeometry(geo);
        const wire = new THREE.LineSegments(
            edges,
            new THREE.LineBasicMaterial({ color: 0x00ffcc, linewidth: 1 })
        );
        cube.add(wire);
        return cube;
    }

    /** Draw a glowing line between two block meshes */
    function connectMeshes(THREE, scene, a, b) {
        const pts = [a.position.clone(), b.position.clone()];
        const geo = new THREE.BufferGeometry().setFromPoints(pts);
        const mat = new THREE.LineBasicMaterial({ color: 0x00ff44, linewidth: 2 });
        const line = new THREE.Line(geo, mat);
        scene.add(line);
        return line;
    }

    /** Float animation (called in render loop) */
    function animateBlock(block, t, i) {
        block.rotation.y = Math.sin(t + i * 0.6) * 0.18;
        block.rotation.x = Math.cos(t * 0.7 + i * 0.3) * 0.09;
        // latest block pulses
        if (block.userData.isLatest) {
            const v = (Math.sin(t * 3) + 1) / 2;
            block.material.emissive.setRGB(0, v * 0.1, v * 0.25);
        }
    }

    /** Scale-up spawn animation */
    function spawnAnimate(block, onDone) {
        block.scale.set(0.01, 0.01, 0.01);
        let frame;
        function step() {
            const s = Math.min(1, block.scale.x + 0.07);
            block.scale.set(s, s, s);
            if (s >= 1) { if (onDone) onDone(); return; }
            frame = requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    /** Build scene lighting */
    function setupLights(THREE, scene) {
        scene.add(new THREE.AmbientLight(0x334455, 0.8));
        const dir = new THREE.DirectionalLight(0x00ffaa, 1);
        dir.position.set(5, 10, 5);
        scene.add(dir);
        const pt = new THREE.PointLight(0x0055ff, 2, 20);
        pt.position.set(0, 5, 0);
        scene.add(pt);
    }

    return { createBlockMesh, connectMeshes, animateBlock, spawnAnimate, setupLights };
})();
