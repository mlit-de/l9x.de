
function secGenerateKey() {
    return crypto.subtle.generateKey( // TODO global
        //{name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: {name: "SHA-256"}},
        {name: "ECDSA", namedCurve: "P-256"},
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"] //can be any combination of "sign" and "verify"
    )
}

async function secImportKey(K) {
    KPUB = Object.assign({},K)
    delete KPUB.d
    KPUB.key_ops=["verify"]

    let key={}
    key.privateKey = await crypto.subtle.importKey("jwk",K,{name: "ECDSA",namedCurve:"P-256"},true, ["sign"])
    key.publicKey = await crypto.subtle.importKey("jwk",KPUB,{name: "ECDSA",namedCurve:"P-256"},true, ["verify"])
    return key
}

async function secSign(privateKey, msg) {
    return window.crypto.subtle.sign(
        // {name: "RSA-PSS", saltLength: 128}, //
        {name: "ECDSA", hash: {name: "SHA-256"}},
        privateKey, //from generateKey or importKey above
        atou8(msg) //ArrayBuffer of data you want to sign
    ).then(s => u8toa(new Uint8Array(s)))
}
function u8toa(a) {
    return btoa(String.fromCharCode(...a))
}

function atou8(a) {
    return new Uint8Array([...atob(a)].map(k => k.charCodeAt(0)))
}
async function hashKey(pubkey) {
    var k = await crypto.subtle.exportKey("jwk", pubkey)
    //var t=JSON.stringify({e:k.e, kty:k.kty, n:k.n})
    var t = JSON.stringify({crv: k.crv, kty: k.kty, x: k.x, y: k.y})
    var a = new TextEncoder().encode(t)
    var h = await window.crypto.subtle.digest({name: "SHA-256"}, a)
    return btoa([...new Uint8Array(h)].map(k => String.fromCodePoint(k)).join(""))
        .replaceAll("/", "_")
        .replaceAll("+", "-")
        .replaceAll("=", "")
}


//----------------------------------------------------------------------------------------

genLink=(hdl,tkn='prompt("rc-token")')=>'javascript:(e=>{var t,a=window,o="message",r=(e,...t)=>e.postMessage(...t);f=(s=>{if(s.source==t&&"connected"==s.data.t){var n=s.ports[0];n["on"+o]=(t=>{(async()=>[await e(t.data)])().catch(e=>[e.message,e.stack]).then(e=>r(t.ports[0],e))}),r(n,{t:"ready",loc:document.location.href}),a.removeEventListener(o,f)}}),a.addEventListener(o,f),t=a.open("https://l9x.de/rc2/C.html#"+'+tkn+')})('+hdl+')';



class RC {

    static get BASE_URL() {
        //return document.location.origin+"/rc/"
        return "https://l9x.de/rc2/"
    }

    constructor({vm,pub,priv,fp}={}) {
        Object.assign(this,{vm,pub,priv,fp})
    }

    _withArgs({vm,pub,priv,fp}={}) {
        vm||=this.vm
        pub||=this.pub
        priv||=this.priv
        fp||=this.fp
        return new RC({vm,pub,priv,fp})
    }

    withVM(txt) {
        return this._withArgs({vm:Promise.reject(txt)})
    }
    loadVM(url) {
        return this._withArgs({vm:fetch(url).then(k=>k.text())})
    }

    setBookmarkInto(selector,{token,prompt}={}) {
        Promise.all([this.vm, prompt ? Promise.resolve(`prompt(${JSON.stringify(prompt)})`) :
            (token ? Promise.resolve(token) : this.fp).then(t=>JSON.stringify(t))]).then(([V,T]) => {
            [...document.querySelectorAll(selector)].forEach(e=>e.href=this._genLink(V, T))
        })
        return this
    }

    genKey() {
        return this._fromPrivateKey(crypto.subtle.generateKey( // TODO global
                {name: "ECDSA", namedCurve: "P-256"},
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["sign", "verify"] //can be any combination of "sign" and "verify"
            ).then(k=>k.privateKey))
    }

    exportKey() {
        return this.priv.then(k=>crypto.subtle.exportKey("jwk", k))
    }

    importKey(key) {
        let priv = crypto.subtle.importKey("jwk", key, {name:"ECDSA", namedCurve: key.crv}, true, ["sign"])
        return this._fromPrivateKey(priv)
    }

    _receiveOnce(wl, hdl) {
        let f = async (e) => {
            while(wl[0]==null) {
                console.log("Waiting ...")
                await new Promise(res => setTimeout(res, 100))
            }
            if(e.source == wl[0]) {
                window.removeEventListener("message",f)
                let H = hdl[e.data.t] || ((data,e) => console.log("Unknown message type", e.data.t, e))
                H(e.data, e)
            }
        }
        window.addEventListener("message", f);

    }

    dispatch(h) {
        return (d,e) => {
            let f=h[e.data.t] || h['*'] || ((data,e) => { console.log("Unknown message type ", data.t, e)});
            f(d, e)
        }
    }


    withNewDispatchPort(h) {
        let mc = new MessageChannel()
        mc.port1.onmessage=this.dispatch(h)
        return mc.port2
    }



    _fromPrivateKey(priv) {
        let pub = priv.then(privKey=>
            crypto.subtle.exportKey("jwk", privKey).then( ({crv,kty,x,y}) =>
                 ({crv,kty,x,y})))

        let fp = pub.then(pubKey =>
            window.crypto.subtle.digest({name: "SHA-256"}, new TextEncoder().encode(JSON.stringify(pubKey))).then(h=>
                btoa(String.fromCodePoint(...new Uint8Array(h)))
                    .replaceAll("/", "_")
                    .replaceAll("+", "-")
                    .replaceAll("=", "")
            )
        )
        return this._withArgs({priv,pub,fp})
    }

    static async _hashKey(pubkey) {
        let k = await crypto.subtle.exportKey("jwk", pubkey)
        let t = JSON.stringify({crv: k.crv, kty: k.kty, x: k.x, y: k.y})
        let h = await window.crypto.subtle.digest({name: "SHA-256"}, new TextEncoder().encode(t))
        return btoa([...new Uint8Array(h)].map(k => String.fromCodePoint(k)).join(""))
    }

    _genLink(hdl,tkn='prompt("rc-token")') {
        let link=`javascript:(e => {
            let t, a = window, o = "message", r = (e, ...t) => e.postMessage(...t);
            f = (s => {
                if (s.source == t && "connected" == s.data.t) {
                    console.log('14: (C->cln): connected',s.data,s);
                    let n = s.ports[0];
                    n["on" + o] = (t => {
                        console.log("21: (srv->cln) ",t.data);
                        (async () => [await e(t.data)])().catch(e => [e.message, e.stack]).then(e => {console.log("R",e);r(t.ports[0], e)})
                    }), r(n, {t: "ready", loc: document.location.href}), a.removeEventListener(o, f)
                }
            }), a.addEventListener(o, f), t = a.open('${RC.BASE_URL}C.html#' + ${tkn})
        })(${hdl})`;
        return link
    }

    registerOnce(wl,hdl) {
        let f = async (e) => {
            while(wl[0]==null) {
                console.log("Waiting for window....")
                await new Promise(res => setTimeout(res, 100))
            }
            if(e.source==wl[0]) {
                window.removeEventListener("message", f)
                this.dispatch(hdl)(e.data,e)
            }
        }
        window.addEventListener("message", f);
    }

    openWindow(onConnect, params) {
        return this._open(onConnect, params, () => {
            return window.open(RC.BASE_URL+"S.html","db-S")
        })
    }
    openFrame(onConnect, params) {
        return this._open(onConnect, params, ()=> {
            let ifr = document.createElement("iframe")
            ifr.src = RC.BASE_URL+"/S.html"
            ifr.height = "50%"
            ifr.width = "100%"
            ifr.style.display = "show" //"none"
            document.body.append(ifr)
            return ifr
        })
    }
    _open(onConnect, {onAccepting, log}={}, opener) {
        log ||= console.log
        onAccepting ||= log
        let wl=[]
        const that=this;

        this.registerOnce(wl, {
            async identify(data, e) {
                 console.log("1: (S->srv) ",e.data)
                 let priv = await that.priv
                 //console.log("1: PRIV", priv, e.data.ch)
                 var sig = await secSign(priv, e.data.ch)
                 let pub = await that.pub
                 //console.log("1: PubK",pub)
                 //console.log({t: "id", sig: sig, pk: pk})
                 var ch=new MessageChannel()
                 ch.port1.onmessage=e=>{
                     var p = e.ports[0]
                     log("12: (C -> srv) "+e.data.t+":",e.data,e)
                     p.onmessage=e=>onConnect(p,e)
                     p.postMessage({t:'connected'})
                 }
                 e.source.postMessage({t: "id", sig: sig, pk: pub}, "*",[ch.port2]);
                 if(onAccepting) {
                     onAccepting(ch.port1)
                 }
            }
        })

        wl[0] = opener();
    }

    static rcall(port, msg) {
        return new Promise((res,rej)=>{
            var ch=new MessageChannel()
            ch.port1.onmessage=e=>{
                console.log("Received ",e)
                e.data.length==1 ? res(e.data[0]) : rej(e.data)
            }
            port.postMessage(msg, [ch.port2])
        })
    }
}
