var nr=0;

var id = Math.floor((Math.random() * 1000) + 1);

fp=[]
portByFp={}
portBySec={}
weakMap=new WeakMap()

onconnect = function (event) {
    const port = event.ports[0];
    port.onmessage = function (e) {
        console.log("(S->W "+id+")", e.data, e)
        if(e.data.t=="register") {
            console.log("3: (S->Worker "+id+") register", e.data)
            portBySec[e.data.sec]=e.ports[0]
            portByFp[e.data.fp]=e.ports[0]
            fp.push(e.data.fp)
            //nr=ports.length
            //ports.push(port)
            //port.postMessage({type: "registered", id: nr})
        } else if(e.data.t=="show") {
            port.postMessage({t:"registered", fp: fp, sec: Object.keys(portBySec)})
        } else if(e.data.t=="clear") {
            portByFp={}
            portBySec={}
            fp=[]
            port.postMessage({t:"registered", fp: Object.keys(portByFp), sec: Object.keys(portBySec)})
        } else if(e.data.t=="connect") {

            var p=portByFp[e.data.fp]
            if(p!=void 0) {
                console.log("11: (C->W "+id+")",e.data, e)
                p.postMessage({t:"connect"}, e.ports)
            } else {
                console.log(`(W ${id}): connect: Unknown`, e.data.t, e.data)
                e.ports[0].postMessage({t:"Worker:Unknown"})
                e.ports[0].close()
            }
        }
        if(e.data.t=="send-debug") {
            var p=portByFp[e.data.trg]
            if(p!=void 0) {
                console.log("Worker:Send-debug")
                p.postMessage(e.data.msg)
            } else {
                console.log("Worker:Unknown-Target")
            }
        }
        /*
        if(e.data.type=="post") {
            ports[e.data.dest].postMessage({type:"post", msg: e.data.msg},e.ports)
        }
         */
    };
};