(() => {
    const results = {};
    return Promise.race([(async () => {
    const privateHttp = __PRIVATE_HTTP_JSON__;
    const privateWs = __PRIVATE_WS_JSON__;
    results.stage = 'fetch';
    try {
        await fetch(privateHttp + '/page-fetch', {mode: 'no-cors'});
        results.fetch = 'proxy-response';
    } catch (_) {
        results.fetch = 'blocked';
    }

    results.stage = 'worker';
    results.worker = await new Promise(resolve => {
        const source = `fetch(${JSON.stringify(privateHttp + '/dedicated-worker')}, {mode:'no-cors'}).then(() => postMessage('proxy-response')).catch(() => postMessage('blocked'));`;
        const worker = new Worker(URL.createObjectURL(new Blob([source], {type:'application/javascript'})));
        const timer = setTimeout(() => { worker.terminate(); resolve('timeout'); }, 3000);
        worker.onmessage = event => { clearTimeout(timer); worker.terminate(); resolve(event.data); };
        worker.onerror = () => { clearTimeout(timer); worker.terminate(); resolve('blocked'); };
    });

    results.stage = 'sharedWorker';
    results.sharedWorker = await new Promise(resolve => {
        const source = `onconnect = event => { const port = event.ports[0]; fetch(${JSON.stringify(privateHttp + '/shared-worker')}, {mode:'no-cors'}).then(() => port.postMessage('proxy-response')).catch(() => port.postMessage('blocked')); };`;
        try {
            const worker = new SharedWorker(URL.createObjectURL(new Blob([source], {type:'application/javascript'})));
            const timer = setTimeout(() => resolve('timeout'), 3000);
            worker.port.onmessage = event => { clearTimeout(timer); resolve(event.data); };
            worker.port.start();
        } catch (_) {
            resolve('blocked');
        }
    });

    results.stage = 'websocket';
    results.websocket = await new Promise(resolve => {
        try {
            const socket = new WebSocket(privateWs + '/socket');
            const timer = setTimeout(() => { socket.close(); resolve('timeout'); }, 3000);
            socket.onopen = () => { clearTimeout(timer); socket.close(); resolve('reached'); };
            socket.onerror = () => { clearTimeout(timer); resolve('blocked'); };
        } catch (_) {
            resolve('blocked');
        }
    });

    results.stage = 'popup';
    results.popup = await new Promise(resolve => {
        const popup = window.open(privateHttp + '/popup', '_blank');
        if (!popup) {
            resolve('blocked');
            return;
        }
        setTimeout(() => {
            try { popup.close(); } catch (_) {}
            resolve('attempted');
        }, 1000);
    });


    results.stage = 'iframe';
    results.iframe = await new Promise(resolve => {
        const frame = document.createElement('iframe');
        const timer = setTimeout(() => { frame.remove(); resolve('attempted'); }, 1000);
        frame.onload = () => { clearTimeout(timer); frame.remove(); resolve('attempted'); };
        frame.onerror = () => { clearTimeout(timer); frame.remove(); resolve('blocked'); };
        frame.src = privateHttp + '/iframe';
        document.body.appendChild(frame);
    });

    results.stage = 'download';
    results.download = await new Promise(resolve => {
        try {
            const anchor = document.createElement('a');
            anchor.href = privateHttp + '/download';
            anchor.download = 'private-probe.txt';
            anchor.target = '_blank';
            anchor.rel = 'noopener noreferrer';
            anchor.style.display = 'none';
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
            resolve('attempted');
        } catch (_) {
            resolve('blocked');
        }
    });

    results.stage = 'redirect';
    results.redirect = await Promise.race([
        fetch(__PUBLIC_REDIRECT_JSON__, {mode:'no-cors', redirect:'follow'})
            .then(() => 'proxy-response')
            .catch(() => 'blocked'),
        new Promise(resolve => setTimeout(() => resolve('timeout'), 3000)),
    ]);

    results.stage = 'serviceWorker';
    results.serviceWorker = await Promise.race([
        new Promise(async resolve => {
        if (!('serviceWorker' in navigator)) {
            resolve('unsupported');
            return;
        }
        try {
            const registration = await navigator.serviceWorker.register('/sw.js', {scope:'/'});
            await navigator.serviceWorker.ready;
            const worker = registration.active || registration.waiting || registration.installing;
            if (!worker) {
                resolve('unavailable');
                return;
            }
            const timer = setTimeout(() => resolve('timeout'), 3000);
            navigator.serviceWorker.addEventListener('message', event => {
                clearTimeout(timer);
                resolve(event.data);
            }, {once:true});
            worker.postMessage('probe');
        } catch (_) {
            resolve('blocked');
        }
        }),        new Promise(resolve => setTimeout(() => resolve('timeout'), 3000)),
    ]);

    results.stage = 'rebinding';
    try {
        await fetch('http://rebind.browser.test:__PRIVATE_PORT__/dns-rebind', {mode:'no-cors'});
        results.rebinding = 'proxy-response';
    } catch (_) {
        results.rebinding = 'blocked';
    }
    results.stage = 'complete';
    return results;
})(), new Promise(resolve => setTimeout(() => { results.globalTimeout = true; resolve(results); }, 12000))]);
})()
