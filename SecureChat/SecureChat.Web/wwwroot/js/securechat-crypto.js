const SC = (() => {
    const RSA = { name: "RSA-OAEP", hash: "SHA-256" };

    const b64 = {
        enc(buf) {
            let s = "";
            for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
            return btoa(s);
        },
        dec: s => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
    };

    // Lưu khóa riêng trong IndexedDB
    const openDb = () => new Promise((res, rej) => {
        const r = indexedDB.open("securechat", 1);
        r.onupgradeneeded = () => r.result.createObjectStore("keys");
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
    });
    const saveKey = async (name, key) => {
        const db = await openDb();
        return new Promise((res, rej) => {
            const tx = db.transaction("keys", "readwrite");
            tx.objectStore("keys").put(key, name);
            tx.oncomplete = res;
            tx.onerror = () => rej(tx.error);
        });
    };
    const loadKey = async name => {
        const db = await openDb();
        return new Promise((res, rej) => {
            const r = db.transaction("keys").objectStore("keys").get(name);
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
        });
    };

    // Sinh khóa lúc đăng ký (khóa riêng để tạm, chờ đăng ký thành công)
    async function generatePending(username) {
        const kp = await crypto.subtle.generateKey(
            { ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
            false, ["wrapKey", "unwrapKey"]);
        await saveKey("pending:" + username.toLowerCase(), kp.privateKey);
        return b64.enc(await crypto.subtle.exportKey("spki", kp.publicKey));
    }
    async function commitPending(username) {
        const u = username.toLowerCase();
        const k = await loadKey("pending:" + u);
        if (k) await saveKey("priv:" + u, k);
    }

    // Lấy khóa công khai người khác
    const cache = new Map();
    async function getPublicKey(username) {
        const u = username.toLowerCase();
        if (!cache.has(u)) {
            const r = await fetch("/api/keys/" + encodeURIComponent(username));
            if (!r.ok) throw new Error(username + " chưa có khóa công khai.");
            const { publicKey } = await r.json();
            cache.set(u, await crypto.subtle.importKey(
                "spki", b64.dec(publicKey), RSA, false, ["wrapKey"]));
        }
        return cache.get(u);
    }

    async function encryptMessage(text, receiver, me) {
        const aes = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, aes, new TextEncoder().encode(text));
        const wrapFor = async user => b64.enc(await crypto.subtle.wrapKey(
            "raw", aes, await getPublicKey(user), RSA));
        return {
            iv: b64.enc(iv),
            ciphertext: b64.enc(ct),
            keyForReceiver: await wrapFor(receiver),
            keyForSender: await wrapFor(me),
        };
    }

    async function decryptMessage(p, sender, me) {
        const priv = await loadKey("priv:" + me.toLowerCase());
        if (!priv) throw new Error("Không có khóa riêng của " + me);
        const wrapped = sender.toLowerCase() === me.toLowerCase()
            ? p.keyForSender : p.keyForReceiver;
        const aes = await crypto.subtle.unwrapKey(
            "raw", b64.dec(wrapped), priv, RSA,
            { name: "AES-GCM" }, false, ["decrypt"]);
        const pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64.dec(p.iv) }, aes, b64.dec(p.ciphertext));
        return new TextDecoder().decode(pt);
    }

    return { generatePending, commitPending, encryptMessage, decryptMessage };
})();