// Independent interpreter and UID. Never imports target modules or reads target stdout.
const http = require('node:http');
const deadline = Date.now() + 4000;
function attempt() {
  const req = http.get({host:'127.0.0.1',port:3210,path:process.argv[2]}, res => {
    const chunks=[]; let size=0;
    res.on('data', chunk => { size+=chunk.length; if(size>4096) process.exit(3); chunks.push(chunk); });
    res.on('end', () => process.stdout.write(JSON.stringify({status:res.statusCode,body:Buffer.concat(chunks).toString('utf8')})));
  });
  req.setTimeout(500,()=>req.destroy(new Error('timeout')));
  req.on('error',()=> { if(Date.now()<deadline) setTimeout(attempt,50); else process.exit(4); });
}
attempt();
